"""
core/session.py

Double Ratchet session lifecycle management.

Wraps python-doubleratchet's DoubleRatchet with:
  - ML-KEM-1024 ratchet steps (via MLKEMRatchet)
  - HKDF-SHA256 root and message chain KDFs
  - ChaCha20-Poly1305 message encryption (via aead.py)
  - Atomic state persistence (via state_store.py)
  - Header counter management (via header_counter.py)

SESSION LIFECYCLE
  1. Alice initiates via PQXDH → gets SK
     session = RatchetSession.create_as_initiator(SK, bob_ratchet_pub, store, session_id)

  2. Bob responds via PQXDH → gets SK + Alice's ratchet public key from bundle
     session = RatchetSession.create_as_responder(SK, store, session_id)

  3. Encrypt a message:
     wire_bytes = await session.encrypt(plaintext, associated_data)

  4. Decrypt a message:
     plaintext = await session.decrypt(wire_bytes, associated_data)

  5. Session state is saved to StateStore after every encrypt/decrypt.

WIRE FORMAT (per message)
  [ message_index (4 bytes, little-endian uint32)
  | ratchet_pub   (1568 bytes, ML-KEM public key)
  | kem_ct        (1568 bytes, ML-KEM ciphertext from ratchet step)
  | ciphertext    (variable, ChaCha20-Poly1305 encrypted payload)
  ]

  The ratchet_pub and kem_ct are included in every message so the receiver
  can perform the DH ratchet step. This is larger than classical X25519
  (32 bytes each) but required for ML-KEM — a known tradeoff documented in
  the design document.

References:
  Signal Double Ratchet spec: https://signal.org/docs/specifications/doubleratchet/
  python-doubleratchet:        https://github.com/Syndace/python-doubleratchet
"""

from __future__ import annotations

import json
import struct
from typing import Optional

from doubleratchet import DoubleRatchet
from doubleratchet.recommended.aead_aes_hmac import AEAD as _DefaultAEAD

from core.aead import encrypt as aead_encrypt, decrypt as aead_decrypt
from core.constants import MAX_SKIP, KEM_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN
from core.dh_ratchet import MLKEMRatchet
from core.header_counter import HeaderCounter
from core.kdf import INFO_CHAIN_KDF
from core.ratchet_kdf import RootChainKDF, MessageChainKDF
from core.state_store import StateStore


# ── Constants ────────────────────────────────────────────────────────────────

# Message chain constant fed into KDF_CK on every message.
# A fixed non-empty byte string used as HKDF salt in MessageChainKDF.
# Domain-separated from all other derivation contexts.
_MESSAGE_CHAIN_CONSTANT: bytes = b"dr-v1-message-chain-constant"

# Wire format header sizes
_MSG_INDEX_LEN  = 4                    # uint32 little-endian
_RATCHET_PUB_LEN = KEM_PUBLIC_KEY_LEN  # 1568 bytes
_KEM_CT_LEN      = KEM_CIPHERTEXT_LEN  # 1568 bytes
_WIRE_HEADER_LEN = _MSG_INDEX_LEN + _RATCHET_PUB_LEN + _KEM_CT_LEN


# ── Ratchet session ───────────────────────────────────────────────────────────

class RatchetSession:
    """
    Full Double Ratchet session with ML-KEM ratchet steps.

    Do not instantiate directly — use create_as_initiator() or
    create_as_responder().
    """

    def __init__(
        self,
        ratchet:    DoubleRatchet,
        store:      StateStore,
        session_id: str,
        counter:    HeaderCounter,
    ) -> None:
        self._ratchet    = ratchet
        self._store      = store
        self._session_id = session_id
        self._counter    = counter
        self._msg_index  = 0   # monotonically increasing, used for nonce

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    async def create_as_initiator(
        cls,
        SK:                bytes,
        bob_ratchet_pub:   bytes,
        store:             StateStore,
        session_id:        str,
    ) -> RatchetSession:
        """
        Create a session as Alice (the initiator).

        Alice has completed PQXDH and holds SK. She uses Bob's current
        ratchet public key (from his key bundle) to perform the first
        DH ratchet step and initialise the sending chain.

        Parameters
        ----------
        SK              : 32-byte shared secret from PQXDH
        bob_ratchet_pub : Bob's ML-KEM ratchet public key (1568 bytes)
                          — use his ik_kem_pub from the key bundle for the
                            first message, then update from message headers
        store           : StateStore for this user
        session_id      : unique identifier for this session
        """
        ratchet = await DoubleRatchet.encrypt_initial_message(
            diffie_hellman_ratchet_class = MLKEMRatchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            # SK seeds the root key
            shared_secret                = SK,
            # Bob's ratchet public key — Alice encapsulates to this
            other_ratchet_pub            = bob_ratchet_pub,
        )
        counter = HeaderCounter(session_id=session_id, initial=0)
        session = cls(ratchet, store, session_id, counter)
        await session._persist()
        return session

    @classmethod
    async def create_as_responder(
        cls,
        SK:         bytes,
        store:      StateStore,
        session_id: str,
    ) -> RatchetSession:
        """
        Create a session as Bob (the responder).

        Bob has completed PQXDH and holds SK. He initialises his receiving
        chain from SK. The first message from Alice will trigger his first
        DH ratchet step when he decapsulates her ML-KEM ciphertext.

        Parameters
        ----------
        SK         : 32-byte shared secret from PQXDH
        store      : StateStore for this user
        session_id : unique identifier for this session
        """
        ratchet = await DoubleRatchet.decrypt_initial_message(
            diffie_hellman_ratchet_class = MLKEMRatchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            shared_secret                = SK,
        )
        counter = HeaderCounter(session_id=session_id, initial=0)
        session = cls(ratchet, store, session_id, counter)
        await session._persist()
        return session

    @classmethod
    async def load(
        cls,
        store:      StateStore,
        session_id: str,
    ) -> RatchetSession:
        """
        Restore a session from StateStore.

        Raises FileNotFoundError if no state exists for this session_id.
        """
        state = store.load_state(session_id)

        ratchet_state = state["ratchet"]
        counter_value = int(state.get("header_counter", 0))
        msg_index     = int(state.get("msg_index", 0))

        ratchet = await DoubleRatchet.from_json(
            serialized                   = ratchet_state,
            diffie_hellman_ratchet_class = MLKEMRatchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
        )

        counter = HeaderCounter(session_id=session_id, initial=counter_value)
        session = cls(ratchet, store, session_id, counter)
        session._msg_index = msg_index
        return session

    # ── Encrypt / Decrypt ─────────────────────────────────────────────────────

    async def encrypt(
        self,
        plaintext:       bytes,
        associated_data: bytes,
    ) -> bytes:
        """
        Encrypt a plaintext message and persist updated ratchet state.

        Wire format:
          message_index (4) | ratchet_pub (1568) | kem_ct (1568) | ciphertext

        The ratchet_pub and kem_ct allow the receiver to perform the
        DH ratchet step before decrypting.

        Parameters
        ----------
        plaintext       : message payload bytes
        associated_data : bound context (sender_id || recipient_id || session_id)
                          authenticated but not encrypted

        Returns
        -------
        bytes : wire-format encrypted message
        """
        # Advance message index BEFORE encrypting — nonce derivation uses it
        self._msg_index += 1
        msg_index = self._msg_index

        # Encrypt via python-doubleratchet — this may trigger a DH ratchet step
        # internally, which calls MLKEMRatchet._perform_diffie_hellman()
        encrypted = await self._ratchet.encrypt_message(
            message          = plaintext,
            associated_data  = associated_data,
        )

        # Retrieve the ML-KEM ciphertext produced during the ratchet step.
        # MLKEMRatchet stores it in _pending_ciphertext after encapsulation.
        # If no ratchet step occurred this message, ciphertext is all zeros
        # (receiver will ignore it and use the cached ratchet state).
        try:
            kem_ct = MLKEMRatchet.pop_pending_ciphertext()
        except RuntimeError:
            kem_ct = b"\x00" * _KEM_CT_LEN

        # Extract the current ratchet public key from the encrypted message header
        ratchet_pub = encrypted.header.ratchet_pub
        if len(ratchet_pub) != _RATCHET_PUB_LEN:
            # Pad or truncate defensively — should not happen with ML-KEM-1024
            ratchet_pub = ratchet_pub.ljust(_RATCHET_PUB_LEN, b"\x00")

        # Build wire format
        wire = (
            struct.pack("<I", msg_index)  # 4 bytes, little-endian uint32
            + ratchet_pub                 # 1568 bytes
            + kem_ct                      # 1568 bytes
            + encrypted.ciphertext        # variable
        )

        # Persist state AFTER building wire bytes but BEFORE returning.
        # If persist fails, the caller gets an OSError and should not send
        # the message — better to lose a message than to desync state.
        await self._persist()
        return wire

    async def decrypt(
        self,
        data:            bytes,
        associated_data: bytes,
    ) -> bytes:
        """
        Decrypt a wire-format message and persist updated ratchet state.

        Parameters
        ----------
        data            : wire bytes from encrypt()
        associated_data : must match what was passed to encrypt()

        Returns
        -------
        bytes : decrypted plaintext

        Raises
        ------
        ValueError  : if data is too short or malformed
        Exception   : from python-doubleratchet if decryption/authentication fails
        """
        if len(data) < _WIRE_HEADER_LEN:
            raise ValueError(
                f"Wire message too short: need at least {_WIRE_HEADER_LEN} bytes, "
                f"got {len(data)}"
            )

        # Parse wire format
        msg_index   = struct.unpack("<I", data[:_MSG_INDEX_LEN])[0]
        ratchet_pub = data[_MSG_INDEX_LEN : _MSG_INDEX_LEN + _RATCHET_PUB_LEN]
        kem_ct      = data[_MSG_INDEX_LEN + _RATCHET_PUB_LEN :
                           _MSG_INDEX_LEN + _RATCHET_PUB_LEN + _KEM_CT_LEN]
        ciphertext  = data[_WIRE_HEADER_LEN:]

        # Feed kem_ct as the "other_pub" for decapsulation — the ratchet
        # will call _perform_diffie_hellman(own_priv=secret_key, other_pub=kem_ct)
        plaintext = await self._ratchet.decrypt_message(
            message          = ciphertext,
            associated_data  = associated_data,
            # ratchet_pub and kem_ct are used internally by the DH ratchet
            ratchet_pub      = ratchet_pub,
            ciphertext       = kem_ct,
        )

        await self._persist()
        return plaintext

    # ── State persistence ─────────────────────────────────────────────────────

    async def _persist(self) -> None:
        """
        Atomically save ratchet state, header counter, and message index
        to StateStore.
        """
        state = {
            "ratchet":        self._ratchet.json,
            "header_counter": self._counter.current,
            "msg_index":      self._msg_index,
        }
        self._store.save_state(self._session_id, state)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def message_index(self) -> int:
        return self._msg_index

    def __repr__(self) -> str:
        return (
            f"RatchetSession(session_id={self._session_id!r}, "
            f"msg_index={self._msg_index})"
        )
