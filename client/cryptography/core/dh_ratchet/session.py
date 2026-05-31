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
    [ msg_index   :  4 bytes, little-endian uint32 — monotonic send counter ]
    [ pn          :  4 bytes, little-endian uint32 — previous_sending_chain_length ]
    [ n           :  4 bytes, little-endian uint32 — sending_chain_length ]
    [ ratchet_pub : 32 bytes, X25519 public key ]
    [ ciphertext  :  variable, ChaCha20-Poly1305 output from DoubleRatchet ]

Total fixed header: 44 bytes.

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

import struct
from doubleratchet import DoubleRatchet
from doubleratchet.types import EncryptedMessage, Header

from core.constants              import MAX_SKIP
from core.dh_ratchet.dh_ratchet  import X25519Ratchet
from core.dh_ratchet.ratchet_kdf import RootChainKDF, MessageChainKDF
from core.header_counter         import HeaderCounter
from core.state_store            import StateStore


# ── Wire format constants ────────────────────────────────────────────────────

# Domain-separated salt fed into MessageChainKDF for every per-message
# derivation. Distinct from every INFO_* string in core/kdf.py — guarded by
# TestMessageChainConstant in testing/test_ratchet.py.
_MESSAGE_CHAIN_CONSTANT: bytes = b"dr-v1-message-chain-constant"

_MSG_INDEX_LEN:      int = 4   # uint32 LE — our monotonic AD counter
_PN_LEN:             int = 4   # uint32 LE — previous_sending_chain_length
_N_LEN:              int = 4   # uint32 LE — sending_chain_length
_RATCHET_PUB_LEN:    int = 32  # X25519 public key

# Byte offsets into the fixed wire header (used in both encrypt and decrypt).
_RATCHET_PUB_OFFSET: int = _MSG_INDEX_LEN + _PN_LEN + _N_LEN   # 12
_WIRE_HEADER_LEN:    int = _RATCHET_PUB_OFFSET + _RATCHET_PUB_LEN  # 44


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
        SK:                bytes,
        bob_ratchet_pub:   bytes,
        store:             StateStore,
        session_id:        str,
    ) -> "RatchetSession":
        """
        Build a session as the initiator (Alice). PQXDH must have completed
        and produced `SK`. `bob_ratchet_pub` is Bob's X25519 ratchet public
        key (32 bytes) from his key bundle.
        """
        if len(SK) != 32:
            raise ValueError(f"SK must be 32 bytes, got {len(SK)}")
        if len(bob_ratchet_pub) != _RATCHET_PUB_LEN:
            raise ValueError(
                f"bob_ratchet_pub must be {_RATCHET_PUB_LEN} bytes, "
                f"got {len(bob_ratchet_pub)}"
            )

        ratchet = await DoubleRatchet.encrypt_initial_message(
            diffie_hellman_ratchet_class = X25519Ratchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            shared_secret                = SK,
            other_ratchet_pub            = bob_ratchet_pub,
        )
        if not isinstance(ratchet, DoubleRatchet):
            raise RuntimeError(
                f"encrypt_initial_message returned unexpected type "
                f"{type(ratchet).__name__!r} — check python-doubleratchet API version."
            )
        session = cls(ratchet, store, session_id, HeaderCounter(session_id=session_id))
        await session._persist()
        return session

    @classmethod
    async def create_as_responder(
        cls,
        SK:         bytes,
        store:      StateStore,
        session_id: str,
    ) -> "RatchetSession":
        """
        Build a session as the responder (Bob). PQXDH must have completed
        and produced `SK`. The first message from Alice will carry her
        X25519 ratchet public key and trigger Bob's first DH ratchet step.
        """
        if len(SK) != 32:
            raise ValueError(f"SK must be 32 bytes, got {len(SK)}")

        ratchet = await DoubleRatchet.decrypt_initial_message(
            diffie_hellman_ratchet_class = X25519Ratchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            shared_secret                = SK,
        )
        if not isinstance(ratchet, DoubleRatchet):
            raise RuntimeError(
                f"decrypt_initial_message returned unexpected type "
                f"{type(ratchet).__name__!r} — check python-doubleratchet API version."
            )
        session = cls(ratchet, store, session_id, HeaderCounter(session_id=session_id))
        await session._persist()
        return session

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
        ratchet = await DoubleRatchet.from_json(
            serialized                   = state["ratchet"],
            diffie_hellman_ratchet_class = X25519Ratchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
        )
        counter = HeaderCounter(
            session_id = session_id,
            initial    = int(state.get("header_counter", 0)),
        )
        session = cls(ratchet, store, session_id, counter)
        session._msg_index = int(state.get("msg_index", 0))
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
        self._msg_index += 1
        msg_index = self._msg_index

        ad_with_index = struct.pack("<I", msg_index) + associated_data

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
            struct.pack("<I", msg_index)
            + struct.pack("<I", pn)
            + struct.pack("<I", n)
            + ratchet_pub
            + encrypted.ciphertext
        )
        await self._persist()
        return wire

    async def decrypt(self, data: bytes, associated_data: bytes) -> bytes:
        """
        Decrypt a wire-format message and return the plaintext.

        Raises
        ------
        ValueError : if `data` is too short to contain the fixed header.
        Exception  : python-doubleratchet propagates authentication and
                     out-of-order failures; the session does not catch them.
        """
        if len(data) < _WIRE_HEADER_LEN:
            raise ValueError(
                f"Wire message too short: need at least {_WIRE_HEADER_LEN} "
                f"bytes for the fixed header, got {len(data)}"
            )

        msg_index   = struct.unpack("<I", data[:_MSG_INDEX_LEN])[0]
        pn          = struct.unpack("<I", data[_MSG_INDEX_LEN : _MSG_INDEX_LEN + _PN_LEN])[0]
        n           = struct.unpack("<I", data[_MSG_INDEX_LEN + _PN_LEN : _RATCHET_PUB_OFFSET])[0]
        ratchet_pub = data[_RATCHET_PUB_OFFSET : _WIRE_HEADER_LEN]
        ciphertext  = data[_WIRE_HEADER_LEN:]

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
        await self._persist()
        return plaintext

    # ── Persistence ──────────────────────────────────────────────────────

    async def _persist(self) -> None:
        """
        Atomically write the full session state to StateStore.

        The state dict has exactly three keys: "ratchet" (the DoubleRatchet's
        own JSON form), "header_counter" (HeaderCounter.current), and
        "msg_index" (this session's send index). Unit tests assert on each
        of these key names.
        """
        state = {
            "ratchet":        self._ratchet.json,
            "header_counter": self._counter.current,
            "msg_index":      self._msg_index,
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
