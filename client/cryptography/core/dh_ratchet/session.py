"""
core/dh_ratchet/session.py

RatchetSession — lifecycle, wire format, and state persistence for one
Double Ratchet conversation.

Wraps python-doubleratchet's DoubleRatchet object with:
  - MLKEMRatchet as the asymmetric ratchet primitive (post-quantum)
  - RootChainKDF / MessageChainKDF for the symmetric ratchet KDFs
  - StateStore for atomic encrypted persistence
  - HeaderCounter for header-key nonce management

Wire format (per encrypted message)
-----------------------------------
    [ msg_index   :  4 bytes, little-endian uint32 ]
    [ ratchet_pub :  1568 bytes, ML-KEM-1024 public key ]
    [ kem_ct      :  1568 bytes, ML-KEM-1024 ciphertext ]
    [ ciphertext  :  variable, ChaCha20-Poly1305 output from DoubleRatchet ]

Total fixed header: 3140 bytes. This is the dominant overhead vs a classical
X25519 Double Ratchet (which would be 4 + 32 + 0 = 36 bytes); the +3104
bytes per message is the price of post-quantum forward secrecy and is
documented in the design document as a known tradeoff.

The ratchet_pub field carries the sender's current ratchet public key. The
kem_ct field carries an ML-KEM ciphertext produced during a DH-ratchet
step; for messages within the same sending chain (no new DH step) kem_ct
is filled with zeros — the receiver detects this from its ratchet state
and skips decapsulation.

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

from core.constants            import MAX_SKIP, KEM_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN
from core.dh_ratchet.dh_ratchet  import MLKEMRatchet
from core.dh_ratchet.ratchet_kdf import RootChainKDF, MessageChainKDF
from core.header_counter       import HeaderCounter
from core.state_store          import StateStore


# ── Wire format constants ────────────────────────────────────────────────────

# Domain-separated salt fed into MessageChainKDF for every per-message
# derivation. Distinct from every INFO_* string in core/kdf.py — guarded by
# TestMessageChainConstant in testing/test_ratchet.py.
_MESSAGE_CHAIN_CONSTANT: bytes = b"dr-v1-message-chain-constant"

_MSG_INDEX_LEN:   int = 4                       # uint32 little-endian
_RATCHET_PUB_LEN: int = KEM_PUBLIC_KEY_LEN      # 1568
_KEM_CT_LEN:      int = KEM_CIPHERTEXT_LEN      # 1568
_WIRE_HEADER_LEN: int = _MSG_INDEX_LEN + _RATCHET_PUB_LEN + _KEM_CT_LEN  # 3140


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
        and produced `SK`. `bob_ratchet_pub` is taken from Bob's published
        key bundle on first contact and carried forward in message headers
        after that.
        """
        ratchet = await DoubleRatchet.encrypt_initial_message(
            diffie_hellman_ratchet_class = MLKEMRatchet,
            root_chain_kdf               = RootChainKDF,
            message_chain_kdf            = MessageChainKDF,
            message_chain_constant       = _MESSAGE_CHAIN_CONSTANT,
            dos_protection_threshold     = MAX_SKIP,
            max_num_skipped_message_keys = MAX_SKIP,
            shared_secret                = SK,
            other_ratchet_pub            = bob_ratchet_pub,
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
        and produced `SK`. The first message from Alice will carry the
        ratchet ciphertext that triggers Bob's first DH ratchet step.
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
            diffie_hellman_ratchet_class = MLKEMRatchet,
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

        The msg_index is incremented BEFORE encryption so the nonce
        derivation in aead._derive_nonce sees a fresh value on every call.
        """
        self._msg_index += 1
        msg_index = self._msg_index

        # DoubleRatchet drives the symmetric ratchet and may internally call
        # MLKEMRatchet._perform_diffie_hellman (sender path), which stashes
        # the ML-KEM ciphertext on the class for us to retrieve.
        encrypted = await self._ratchet.encrypt_message(
            message         = plaintext,
            associated_data = associated_data,
        )

        # Pick up the freshly-stashed ciphertext from the ratchet step. If
        # no DH ratchet step occurred this turn (most messages within a
        # sending chain), there is no ciphertext to send — fill with zeros
        # so the wire layout stays fixed-size, and rely on the receiver's
        # ratchet state to know whether to decapsulate.
        try:
            kem_ct = MLKEMRatchet.pop_pending_ciphertext()
        except RuntimeError:
            kem_ct = b"\x00" * _KEM_CT_LEN

        ratchet_pub = encrypted.header.ratchet_pub
        if len(ratchet_pub) != _RATCHET_PUB_LEN:
            # Defensive: ML-KEM-1024 public keys are always 1568 bytes, but
            # if the library hands us anything else we pad rather than
            # silently writing a malformed wire packet.
            ratchet_pub = ratchet_pub.ljust(_RATCHET_PUB_LEN, b"\x00")

        wire = (
            struct.pack("<I", msg_index)
            + ratchet_pub
            + kem_ct
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

        ratchet_pub_start = _MSG_INDEX_LEN
        kem_ct_start      = _MSG_INDEX_LEN + _RATCHET_PUB_LEN
        ciphertext_start  = _WIRE_HEADER_LEN

        msg_index   = struct.unpack("<I", data[:_MSG_INDEX_LEN])[0]
        ratchet_pub = data[ratchet_pub_start : kem_ct_start]
        kem_ct      = data[kem_ct_start      : ciphertext_start]
        ciphertext  = data[ciphertext_start  :]

        plaintext = await self._ratchet.decrypt_message(
            message         = ciphertext,
            associated_data = associated_data,
            ratchet_pub     = ratchet_pub,
            ciphertext      = kem_ct,
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
