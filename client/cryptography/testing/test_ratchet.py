"""
tests/test_ratchet.py

Unit tests for:
  core/dh_ratchet.py   — X25519 DiffieHellmanRatchet subclass
  core/ratchet_kdf.py  — Root and message chain KDF implementations
  core/session.py      — RatchetSession lifecycle

Tests are split into three groups:
  - ratchet_kdf:   fully testable without mocks (pure HKDF)
  - dh_ratchet:    uses real cryptography library (no external dependencies)
  - session:       testable with mocked DoubleRatchet (lifecycle and persistence)

Run with: pytest testing/test_ratchet.py -v
"""

import struct
import pytest
from unittest.mock import AsyncMock, MagicMock, PropertyMock


# ══════════════════════════════════════════════════════════════════════════════
# RootChainKDF and MessageChainKDF
# These are pure HKDF wrappers — fully testable without any mocks.
# ══════════════════════════════════════════════════════════════════════════════

class TestRootChainKDF:
    """
    RootChainKDF wraps HKDF-SHA256 with INFO_ROOT_KDF.
    Signal DR spec §3.1 KDF_RK: takes (root_key, dh_output) → 64 bytes.
    The root key is the HKDF salt; the DH output is the IKM.
    """

    @pytest.fixture
    def kdf(self):
        from core.dh_ratchet.ratchet_kdf import RootChainKDF
        return RootChainKDF

    def test_output_length_respected(self, kdf):
        key  = b"r" * 32
        data = b"d" * 32
        assert len(kdf.calculate(64, key, data)) == 64
        assert len(kdf.calculate(32, key, data)) == 32

    def test_is_deterministic(self, kdf):
        key  = b"r" * 32
        data = b"d" * 32
        assert kdf.calculate(64, key, data) == kdf.calculate(64, key, data)

    def test_different_keys_produce_different_output(self, kdf):
        data = b"d" * 32
        out1 = kdf.calculate(64, b"k" * 32, data)
        out2 = kdf.calculate(64, b"z" * 32, data)
        assert out1 != out2

    def test_different_data_produces_different_output(self, kdf):
        key  = b"r" * 32
        out1 = kdf.calculate(64, key, b"a" * 32)
        out2 = kdf.calculate(64, key, b"b" * 32)
        assert out1 != out2

    def test_output_not_equal_to_key_or_data(self, kdf):
        """HKDF must transform its input — not echo it."""
        key  = b"r" * 32
        data = b"d" * 32
        out  = kdf.calculate(64, key, data)
        assert out[:32] != key
        assert out[:32] != data

    def test_uses_root_kdf_info_string(self, kdf):
        """
        Verify INFO_ROOT_KDF is used by checking output differs from
        a call with INFO_CHAIN_KDF. If info strings were swapped,
        root and chain keys would collide.
        """
        from core.dh_ratchet.ratchet_kdf import MessageChainKDF
        key  = b"k" * 32
        data = b"d" * 32
        root_out  = kdf.calculate(64, key, data)
        chain_out = MessageChainKDF.calculate(64, key, data)
        assert root_out != chain_out

    def test_first_32_bytes_is_new_root_key(self, kdf):
        """
        By convention, python-doubleratchet uses the first 32 bytes as the
        new root key and the next 32 as the new chain key.
        Verify the output is 64 bytes that can be split this way.
        """
        out = kdf.calculate(64, b"r" * 32, b"d" * 32)
        new_root_key  = out[:32]
        new_chain_key = out[32:]
        assert len(new_root_key)  == 32
        assert len(new_chain_key) == 32
        assert new_root_key != new_chain_key

    def test_successive_root_kdf_steps_produce_different_keys(self, kdf):
        """
        Simulate two consecutive DH ratchet steps.
        Each step's root key becomes the next step's salt.
        All outputs must be unique.
        """
        root_key = b"initial_root_key" * 2   # 32 bytes
        seen = set()
        for i in range(5):
            dh_out   = bytes([i] * 32)
            out      = kdf.calculate(64, root_key, dh_out)
            root_key = out[:32]
            chain_key = out[32:]
            assert out not in seen
            seen.add(out)


class TestMessageChainKDF:
    """
    MessageChainKDF wraps HKDF-SHA256 with INFO_CHAIN_KDF.
    Signal DR spec §3.1 KDF_CK: takes chain_key → message_key + next_chain_key.
    """

    @pytest.fixture
    def kdf(self):
        from core.dh_ratchet.ratchet_kdf import MessageChainKDF
        return MessageChainKDF

    def test_output_length_respected(self, kdf):
        key  = b"c" * 32
        data = b"constant"
        assert len(kdf.calculate(64, key, data)) == 64

    def test_is_deterministic(self, kdf):
        key  = b"c" * 32
        data = b"constant"
        assert kdf.calculate(64, key, data) == kdf.calculate(64, key, data)

    def test_different_chain_keys_produce_different_output(self, kdf):
        data = b"constant"
        assert (kdf.calculate(64, b"a" * 32, data) !=
                kdf.calculate(64, b"b" * 32, data))

    def test_successive_chain_steps_produce_unique_keys(self, kdf):
        """
        Simulate 10 message keys derived from a single chain.
        Each step uses the second 32 bytes as the next chain key.
        All message keys must be unique — no two messages share a key.
        """
        chain_key = b"initial_chain_key" * 2   # 32 bytes
        constant  = b"dr-v1-message-chain-constant"
        seen = set()
        for _ in range(10):
            out        = kdf.calculate(64, chain_key, constant)
            msg_key    = out[:32]
            chain_key  = out[32:]
            assert msg_key not in seen, "Message key collision — two messages share a key"
            seen.add(msg_key)

    def test_message_key_differs_from_next_chain_key(self, kdf):
        """Message key and next chain key must be distinct."""
        out = kdf.calculate(64, b"c" * 32, b"constant")
        assert out[:32] != out[32:]

    def test_domain_separation_from_root_kdf(self, kdf):
        """
        MessageChainKDF and RootChainKDF must produce different outputs
        for the same inputs — their INFO_* strings must differ.
        """
        from core.dh_ratchet.ratchet_kdf import RootChainKDF
        key  = b"k" * 32
        data = b"d" * 32
        assert kdf.calculate(64, key, data) != RootChainKDF.calculate(64, key, data)


# ══════════════════════════════════════════════════════════════════════════════
# X25519Ratchet
# Tests key generation and DH exchange. Uses real cryptography — no mocks
# needed since the cryptography library has no external dependencies.
# ══════════════════════════════════════════════════════════════════════════════

class TestX25519Ratchet:

    def test_generate_key_pair_returns_correct_sizes(self):
        from core.dh_ratchet.dh_ratchet import X25519Ratchet
        pub, priv = X25519Ratchet._generate_key_pair()
        assert len(pub)  == 32
        assert len(priv) == 32

    def test_generate_key_pair_produces_different_keys(self):
        from core.dh_ratchet.dh_ratchet import X25519Ratchet
        pub1, _ = X25519Ratchet._generate_key_pair()
        pub2, _ = X25519Ratchet._generate_key_pair()
        assert pub1 != pub2

    def test_dh_produces_32_byte_shared_secret(self):
        from core.dh_ratchet.dh_ratchet import X25519Ratchet
        pub_a, priv_a = X25519Ratchet._generate_key_pair()
        pub_b, priv_b = X25519Ratchet._generate_key_pair()
        ss = X25519Ratchet._perform_diffie_hellman(priv_a, pub_b)
        assert len(ss) == 32

    def test_dh_is_symmetric(self):
        """X25519(a_priv, b_pub) == X25519(b_priv, a_pub)."""
        from core.dh_ratchet.dh_ratchet import X25519Ratchet
        pub_a, priv_a = X25519Ratchet._generate_key_pair()
        pub_b, priv_b = X25519Ratchet._generate_key_pair()
        ss_a = X25519Ratchet._perform_diffie_hellman(priv_a, pub_b)
        ss_b = X25519Ratchet._perform_diffie_hellman(priv_b, pub_a)
        assert ss_a == ss_b

    def test_different_key_pairs_produce_different_secrets(self):
        from core.dh_ratchet.dh_ratchet import X25519Ratchet
        pub_a, priv_a = X25519Ratchet._generate_key_pair()
        pub_b, priv_b = X25519Ratchet._generate_key_pair()
        pub_c, priv_c = X25519Ratchet._generate_key_pair()
        ss_ab = X25519Ratchet._perform_diffie_hellman(priv_a, pub_b)
        ss_ac = X25519Ratchet._perform_diffie_hellman(priv_a, pub_c)
        assert ss_ab != ss_ac


# ══════════════════════════════════════════════════════════════════════════════
# Wire format constants
# No mocks needed — these just validate the wire layout arithmetic.
# ══════════════════════════════════════════════════════════════════════════════

class TestWireFormat:
    """
    Verify wire format constants match the expected layout.
    These are important for the design document and interview.
    """

    def test_wire_header_length(self):
        """
        Wire header = version (1) + msg_index (4) + pn (4) + n (4) + ratchet_pub (32) = 45 bytes.
        pn and n carry the DoubleRatchet Header chain-length fields so the
        receiver can reconstruct the full Header for out-of-order handling.
        """
        from core.dh_ratchet.session import (
            _WIRE_HEADER_LEN, _WIRE_VERSION_LEN, _MSG_INDEX_LEN, _PN_LEN, _N_LEN, _RATCHET_PUB_LEN,
        )
        assert _WIRE_HEADER_LEN == _WIRE_VERSION_LEN + _MSG_INDEX_LEN + _PN_LEN + _N_LEN + _RATCHET_PUB_LEN
        assert _WIRE_HEADER_LEN == 45

    def test_message_index_encoding(self):
        """message_index is uint32 little-endian — verify decode."""
        for idx in [0, 1, 1000, 2**32 - 1]:
            encoded = struct.pack("<I", idx)
            decoded = struct.unpack("<I", encoded)[0]
            assert decoded == idx

    def test_ratchet_pub_length(self):
        """X25519 public key is 32 bytes."""
        from core.dh_ratchet.session import _RATCHET_PUB_LEN
        assert _RATCHET_PUB_LEN == 32


# ══════════════════════════════════════════════════════════════════════════════
# RatchetSession persistence
# Mocks DoubleRatchet and StateStore to test the session layer in isolation.
# ══════════════════════════════════════════════════════════════════════════════

class TestRatchetSessionPersistence:

    @pytest.fixture
    def mock_store(self, tmp_path):
        """A real StateStore backed by tmp_path — no encryption mock needed."""
        from core.state_store import StateStore
        return StateStore.create(tmp_path / "state", passphrase="test")

    @pytest.fixture
    def mock_ratchet(self):
        """Mock DoubleRatchet — we're testing session lifecycle, not DR internals."""
        ratchet = MagicMock()
        type(ratchet).json = PropertyMock(return_value={"mock": "state"})
        ratchet.encrypt_message = AsyncMock()
        ratchet.decrypt_message = AsyncMock(return_value=b"plaintext")
        return ratchet

    @pytest.fixture
    def session(self, mock_store, mock_ratchet):
        from core.dh_ratchet.session import RatchetSession
        from core.header_counter import HeaderCounter
        counter = HeaderCounter(session_id="test-session")
        s = RatchetSession(mock_ratchet, mock_store, "test-session", counter)
        return s

    def test_persist_saves_ratchet_state(self, session, mock_store):
        session._persist()
        assert mock_store.state_exists("test-session")

    def test_persist_saves_message_index(self, session, mock_store):
        session._msg_index = 7
        session._persist()
        state = mock_store.load_state("test-session")
        assert state["msg_index"] == 7

    def test_persist_saves_header_counter(self, session, mock_store):
        session._counter._counter = 5
        session._persist()
        state = mock_store.load_state("test-session")
        assert state["header_counter"] == 5

    @pytest.mark.asyncio
    async def test_message_index_increments_on_encrypt(self, session, mock_ratchet):
        """message_index must increment before encryption — it is prepended to AD."""
        header = MagicMock()
        header.ratchet_pub                   = b"\xaa" * 32
        header.previous_sending_chain_length = 0
        header.sending_chain_length          = 1
        encrypted = MagicMock()
        encrypted.header     = header
        encrypted.ciphertext = b"\xbb" * 32
        mock_ratchet.encrypt_message.return_value = encrypted

        assert session._msg_index == 0
        await session.encrypt(b"hello", b"ad")
        assert session._msg_index == 1

    @pytest.mark.asyncio
    async def test_wire_too_short_raises(self, session):
        from core.signatures import SignedCiphertext
        from core.constants import HYBRID_SIGNATURE_LEN
        signed = SignedCiphertext(
            ciphertext=b"\x00" * 10,
            signature=b"\x00" * HYBRID_SIGNATURE_LEN,
            sender_id=b"alice",
            recipient_id=b"bob",
            message_index=1,
        )
        with pytest.raises(ValueError, match="too short"):
            await session.decrypt(signed, b"ad")

    def test_session_id_property(self, session):
        assert session.session_id == "test-session"

    def test_repr(self, session):
        assert "test-session" in repr(session)
        assert "msg_index" in repr(session)


# ══════════════════════════════════════════════════════════════════════════════
# Message chain constant
# ══════════════════════════════════════════════════════════════════════════════

class TestMessageChainConstant:

    def test_constant_is_nonempty_bytes(self):
        from core.dh_ratchet.session import _MESSAGE_CHAIN_CONSTANT
        assert isinstance(_MESSAGE_CHAIN_CONSTANT, bytes)
        assert len(_MESSAGE_CHAIN_CONSTANT) > 0

    def test_constant_is_domain_separated(self):
        """Chain constant must not equal any INFO_* string from kdf.py."""
        from core.dh_ratchet.session import _MESSAGE_CHAIN_CONSTANT
        from core.kdf import (
            INFO_ROOT_KDF, INFO_CHAIN_KDF, INFO_HEADER_KEY,
            INFO_LOCAL_KEY_ENC, INFO_PQXDH_SK
        )
        for info in [INFO_ROOT_KDF, INFO_CHAIN_KDF,
                     INFO_HEADER_KEY, INFO_LOCAL_KEY_ENC, INFO_PQXDH_SK]:
            assert _MESSAGE_CHAIN_CONSTANT != info
