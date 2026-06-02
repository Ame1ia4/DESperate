"""
core/dh_ratchet/session.py

RatchetSession — lifecycle, wire format, and state persistence for one
Double Ratchet conversation.

Wraps python-doubleratchet's DoubleRatchet object with:
  - X25519Ratchet as the DH ratchet primitive (classical X25519)
  - RootChainKDF / MessageChainKDF for the symmetric ratchet KDFs
  - StateStore for atomic encrypted persistence
  - HeaderCounter for header-key nonce management

Wire format (per encrypted message)
-----------------------------------
    [ version     :  1 byte,  0x02 — format version tag ]
    [ msg_index   :  4 bytes, little-endian uint32 — monotonic send counter ]
    [ pn          :  4 bytes, little-endian uint32 — previous_sending_chain_length ]
    [ n           :  4 bytes, little-endian uint32 — sending_chain_length ]
    [ ratchet_pub : 32 bytes, X25519 public key ]
    [ ciphertext  :  variable, ChaCha20-Poly1305 output from DoubleRatchet ]

Total fixed header: 45 bytes.

The version byte lets the decoder immediately reject messages from incompatible
client versions (e.g. old 3148-byte format) with a diagnostic error instead of
silently passing the 44-byte minimum-length guard and decoding garbage fields.

pn and n mirror the fields in the DoubleRatchet Header so the receiver can
reconstruct the Header for decrypt_message() and handle out-of-order delivery
correctly. Without them, the library cannot locate skipped message keys.

AEAD coverage
-------------
msg_index is prepended to the associated_data passed to DoubleRatchet so the
wire counter is covered by the AEAD tag — a MITM cannot silently reorder
messages by flipping it. ratchet_pub, pn, and n are authenticated by
DoubleRatchet internally (the library includes the serialised Header in the
AEAD associated data).

Persistence
-----------
After every encrypt and decrypt, the session writes its full state to
StateStore atomically. The persisted dict has exactly three keys:
    {
        "ratchet":        <DoubleRatchet.json — opaque to this layer>,
        "header_counter": <int — current HeaderCounter value>,
        "msg_index":      <int — monotonically increasing send index>,
    }
If the write fails the caller receives an OSError before the wire bytes
are returned, so the message is never sent with stale state on disk.

References
----------
Signal Double Ratchet spec:
    https://signal.org/docs/specifications/doubleratchet/
python-doubleratchet (Syndace):
    https://github.com/Syndace/python-doubleratchet
"""
from __future__ import annotations

import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from doubleratchet import AEAD, DoubleRatchet
from doubleratchet.types import EncryptedMessage, Header

from core.constants              import MAX_SKIP
from core.dh_ratchet.dh_ratchet  import X25519Ratchet
from core.dh_ratchet.ratchet_kdf import RootChainKDF, MessageChainKDF
from core.header_counter         import HeaderCounter
from core.signatures             import SignedCiphertext
from core.state_store            import StateStore


# ── Wire format constants ────────────────────────────────────────────────────

# Domain-separated salt fed into MessageChainKDF for every per-message
# derivation. Distinct from every INFO_* string in core/kdf.py — guarded by
# TestMessageChainConstant in testing/test_ratchet.py.
_MESSAGE_CHAIN_CONSTANT: bytes = b"dr-v1-message-chain-constant"

_WIRE_VERSION:       bytes = b"\x02"  # format version — rejects old-format messages
_WIRE_VERSION_LEN:   int   = 1
_MSG_INDEX_LEN:      int   = 4   # uint32 LE — our monotonic AD counter
_PN_LEN:             int   = 4   # uint32 LE — previous_sending_chain_length
_N_LEN:              int   = 4   # uint32 LE — sending_chain_length
_RATCHET_PUB_LEN:    int   = 32  # X25519 public key

# Byte offsets into the fixed wire header (used in both encrypt and decrypt).
_MSG_INDEX_OFFSET:   int = _WIRE_VERSION_LEN                              # 1
_PN_OFFSET:          int = _MSG_INDEX_OFFSET   + _MSG_INDEX_LEN           # 5
_N_OFFSET:           int = _PN_OFFSET          + _PN_LEN                  # 9
_RATCHET_PUB_OFFSET: int = _N_OFFSET           + _N_LEN                  # 13
_WIRE_HEADER_LEN:    int = _RATCHET_PUB_OFFSET + _RATCHET_PUB_LEN        # 45


# ── AEAD adapter for python-doubleratchet v1.x ───────────────────────────────

class _RatchetAEAD(AEAD):
    """ChaCha20-Poly1305 AEAD for the python-doubleratchet library."""

    @staticmethod
    async def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data)

    @staticmethod
    async def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        return ChaCha20Poly1305(key).decrypt(ciphertext[:12], ciphertext[12:], associated_data)


# ── Concrete DoubleRatchet subclass ───────────────────────────────────────────

class _DR(DoubleRatchet):
    """
    Concrete DoubleRatchet with _build_associated_data implemented.

    Combines the caller's associated data with a unique, length-prefixed
    encoding of the message header so the AEAD covers both.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            struct.pack(">I", len(associated_data))
            + associated_data
            + header.ratchet_pub
            + struct.pack(">I", header.previous_sending_chain_length)
            + struct.pack(">I", header.sending_chain_length)
        )


# ── Session ──────────────────────────────────────────────────────────────────

class RatchetSession:
    """
    One Double Ratchet conversation, persisted to disk.

    Construct directly when you already hold a DoubleRatchet instance (e.g.
    from a factory or a `DoubleRatchet.from_json` restore). For the normal
    "start a new session" and "load an existing session" flows, use the
    factory classmethods `create_as_initiator` / `create_as_responder` /
    `load`.

    The constructor signature `(ratchet, store, session_id, counter)` is
    intentionally minimal and is exercised directly by the unit tests with
    a mocked DoubleRatchet.
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
        self._msg_index  = 0

    # ── Factories ────────────────────────────────────────────────────────

    @classmethod
    async def create_as_initiator(
        cls,
        SK:              bytes,
        bob_ratchet_pub: bytes,
        plaintext:       bytes,
        associated_data: bytes,
        store:           StateStore,
        session_id:      str,
    ) -> "Tuple[RatchetSession, bytes]":
        """
        Build a session as the initiator (Alice) AND encrypt the first message.

        python-doubleratchet >=1.0 bundles the first encrypted message with
        session creation. Returns (session, wire_bytes).
        """
        if len(SK) != 32:
            raise ValueError(f"SK must be 32 bytes, got {len(SK)}")
        if len(bob_ratchet_pub) != _RATCHET_PUB_LEN:
            raise ValueError(f"bob_ratchet_pub must be {_RATCHET_PUB_LEN} bytes, got {len(bob_ratchet_pub)}")

        next_index    = 1
        ad_with_index = struct.pack("<I", next_index) + associated_data

        ratchet, encrypted = await _DR.encrypt_initial_message(
            diffie_hellman_ratchet_class = X25519Ratchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            aead                         = _RatchetAEAD,
            shared_secret                = SK,
            recipient_ratchet_pub        = bob_ratchet_pub,
            message                      = plaintext,
            associated_data              = ad_with_index,
        )

        ratchet_pub = encrypted.header.ratchet_pub
        pn          = encrypted.header.previous_sending_chain_length
        n           = encrypted.header.sending_chain_length

        wire = (
            _WIRE_VERSION
            + struct.pack("<I", next_index)
            + struct.pack("<I", pn)
            + struct.pack("<I", n)
            + ratchet_pub
            + encrypted.ciphertext
        )

        session = cls(ratchet, store, session_id, HeaderCounter(session_id=session_id))
        session._msg_index = next_index
        session._persist()
        return session, wire

    @classmethod
    async def create_as_responder(
        cls,
        SK:               bytes,
        own_ratchet_priv: bytes,
        wire_bytes:       bytes,
        associated_data:  bytes,
        store:            StateStore,
        session_id:       str,
    ) -> "Tuple[RatchetSession, bytes]":
        """
        Build a session as the responder (Bob) AND decrypt the first message.

        `own_ratchet_priv` is Bob's SPK private key (32 bytes).
        Returns (session, plaintext).
        """
        if len(SK) != 32:
            raise ValueError(f"SK must be 32 bytes, got {len(SK)}")
        if len(wire_bytes) < _WIRE_HEADER_LEN:
            raise ValueError(f"Wire message too short for initial message")
        if wire_bytes[0:1] != _WIRE_VERSION:
            raise ValueError(f"Incompatible wire format version 0x{wire_bytes[0]:02x}")

        msg_index   = struct.unpack("<I", wire_bytes[_MSG_INDEX_OFFSET:_PN_OFFSET])[0]
        pn          = struct.unpack("<I", wire_bytes[_PN_OFFSET:_N_OFFSET])[0]
        n           = struct.unpack("<I", wire_bytes[_N_OFFSET:_RATCHET_PUB_OFFSET])[0]
        ratchet_pub = wire_bytes[_RATCHET_PUB_OFFSET:_WIRE_HEADER_LEN]
        ciphertext  = wire_bytes[_WIRE_HEADER_LEN:]

        ad_with_index = struct.pack("<I", msg_index) + associated_data

        encrypted_msg = EncryptedMessage(
            header=Header(
                ratchet_pub                   = ratchet_pub,
                previous_sending_chain_length = pn,
                sending_chain_length          = n,
            ),
            ciphertext=ciphertext,
        )

        ratchet, plaintext = await _DR.decrypt_initial_message(
            diffie_hellman_ratchet_class = X25519Ratchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            aead                         = _RatchetAEAD,
            shared_secret                = SK,
            own_ratchet_priv             = own_ratchet_priv,
            message                      = encrypted_msg,
            associated_data              = ad_with_index,
        )

        session = cls(ratchet, store, session_id, HeaderCounter(session_id=session_id))
        session._persist()
        return session, plaintext

    @classmethod
    async def load(
        cls,
        store:      StateStore,
        session_id: str,
    ) -> "RatchetSession":
        """
        Restore a session from StateStore. Raises FileNotFoundError (via
        StateStore.load_state) if no persisted state exists.
        """
        state = store.load_state(session_id)
        ratchet = _DR.from_json(
            serialized                   = state["ratchet"],
            diffie_hellman_ratchet_class = X25519Ratchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            aead                         = _RatchetAEAD,
        )
        counter = HeaderCounter(
            session_id = session_id,
            initial    = int(state.get("header_counter", 0)),
        )
        if "msg_index" not in state:
            raise KeyError(
                f"Persisted state for session {session_id!r} is missing 'msg_index'. "
                "State may have been written by an incompatible client version."
            )
        session = cls(ratchet, store, session_id, counter)
        session._msg_index = int(state["msg_index"])
        return session

    # ── Encrypt / Decrypt ────────────────────────────────────────────────

    async def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        """
        Encrypt `plaintext` and return the wire-format bytes.

        The state on disk is updated atomically before the call returns. If
        persistence fails the wire bytes are NOT returned — better to lose a
        message than to ship one whose state on disk doesn't match.

        msg_index is prepended to associated_data before passing to
        DoubleRatchet so the wire counter is covered by the AEAD tag.
        """
        next_index = self._msg_index + 1
        ad_with_index = struct.pack("<I", next_index) + associated_data

        encrypted = await self._ratchet.encrypt_message(
            message         = plaintext,
            associated_data = ad_with_index,
        )

        ratchet_pub = encrypted.header.ratchet_pub
        if len(ratchet_pub) != _RATCHET_PUB_LEN:
            raise ValueError(
                f"ratchet_pub has unexpected length {len(ratchet_pub)} "
                f"(expected {_RATCHET_PUB_LEN}). Library state may be corrupt."
            )

        pn = encrypted.header.previous_sending_chain_length
        n  = encrypted.header.sending_chain_length

        wire = (
            _WIRE_VERSION
            + struct.pack("<I", next_index)
            + struct.pack("<I", pn)
            + struct.pack("<I", n)
            + ratchet_pub
            + encrypted.ciphertext
        )
        # Persist before committing to memory — if the write fails, the index is
        # not advanced and the next encrypt will retry with the same index.
        self._persist(pending_msg_index=next_index)
        self._msg_index = next_index
        return wire

    async def decrypt(self, signed: SignedCiphertext, associated_data: bytes) -> bytes:
        """
        Decrypt a verified SignedCiphertext and return the plaintext.

        `signed` MUST have been obtained via verify_and_extract() (or
        verify_ciphertext() followed by SignedCiphertext.from_bytes()). Accepting
        SignedCiphertext rather than raw bytes makes skipping verification a
        deliberate choice rather than the path of least resistance.

        Raises
        ------
        ValueError : if the ratchet wire payload is too short or empty.
        Exception  : python-doubleratchet propagates authentication and
                     out-of-order failures; the session does not catch them.
        """
        data = signed.ciphertext
        if len(data) < _WIRE_HEADER_LEN:
            raise ValueError(
                f"Wire message too short: need at least {_WIRE_HEADER_LEN} "
                f"bytes for the fixed header, got {len(data)}"
            )

        if data[0:1] != _WIRE_VERSION:
            raise ValueError(
                f"Incompatible wire format: expected version byte "
                f"0x{_WIRE_VERSION.hex()}, got 0x{data[0]:02x}. "
                f"Message may be from an incompatible client version."
            )

        msg_index   = struct.unpack("<I", data[_MSG_INDEX_OFFSET : _PN_OFFSET])[0]
        pn          = struct.unpack("<I", data[_PN_OFFSET         : _N_OFFSET])[0]
        n           = struct.unpack("<I", data[_N_OFFSET          : _RATCHET_PUB_OFFSET])[0]
        ratchet_pub = data[_RATCHET_PUB_OFFSET : _WIRE_HEADER_LEN]
        ciphertext  = data[_WIRE_HEADER_LEN:]
        if not ciphertext:
            raise ValueError("Wire message has an empty ciphertext body.")

        ad_with_index = struct.pack("<I", msg_index) + associated_data

        plaintext = await self._ratchet.decrypt_message(
            message = EncryptedMessage(
                header = Header(
                    ratchet_pub                   = ratchet_pub,
                    previous_sending_chain_length = pn,
                    sending_chain_length          = n,
                ),
                ciphertext = ciphertext,
            ),
            associated_data = ad_with_index,
        )
        self._persist()
        return plaintext

    # ── Persistence ──────────────────────────────────────────────────────

    def _persist(self, pending_msg_index: int | None = None) -> None:
        """
        Atomically write the full session state to StateStore.

        The state dict has exactly three keys: "ratchet" (the DoubleRatchet's
        own JSON form), "header_counter" (HeaderCounter.current), and
        "msg_index" (this session's send index). Unit tests assert on each
        of these key names.

        pending_msg_index: if provided, written as msg_index instead of
        self._msg_index. Used by encrypt() to persist the new index before
        committing it to memory, so a failed write never advances the counter.
        """
        state = {
            "ratchet":        self._ratchet.json,
            "header_counter": self._counter.current,
            "msg_index":      pending_msg_index if pending_msg_index is not None else self._msg_index,
        }
        self._store.save_state(self._session_id, state)

    # ── Properties ────────────────────────────────────────────────────────

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
