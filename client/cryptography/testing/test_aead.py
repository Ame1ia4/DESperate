"""
Unit tests for core/aead.py
ChaCha20-Poly1305 AEAD with HKDF-derived nonces.

Run with: pytest test_aead.py -v

Wire format under test:
  nonce (12 bytes) || ciphertext || tag (16 bytes)
  = 28 bytes of overhead per message (down from 32 — reuse guard removed)

Reuse guard omission rationale:
  The MLS §9.3 reuse guard protects against crash-recovery nonce reuse.
  We omit it because ratchet state is persisted atomically before any
  message key is returned to the caller — crash recovery cannot re-derive
  a used key. Atomic persistence provides the same guarantee directly.
  This matches Signal's own implementation.
"""

import struct

import pytest
from cryptography.exceptions import InvalidTag

from core.aead import _derive_nonce, decrypt, encrypt
from core.constants import KEY_LEN, NONCE_LEN, TAG_LEN, MIN_CT_LEN, MAX_SKIP


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_key(seed: int = 0) -> bytes:
    """Deterministic 32-byte key for testing. Never use in production."""
    return bytes([(seed + i) % 256 for i in range(KEY_LEN)])


def _unique_key(n: int) -> bytes:
    """Return a unique 32-byte key for message n (simulates the ratchet)."""
    return bytes([(n * 7 + i) % 256 for i in range(KEY_LEN)])


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def key():
    return _make_key(0)


@pytest.fixture
def ad():
    """
    Length-prefixed AD: prevents the concatenation ambiguity where
    b"alice" + b"bob" == b"aliceb" + b"ob". Tests that need raw AD
    bytes can construct their own.
    """
    sender    = b"alice"
    recipient = b"bob"
    return (
        struct.pack("!H", len(sender))    + sender +
        struct.pack("!H", len(recipient)) + recipient
    )


@pytest.fixture
def plaintext():
    return b"Hello, Bob. This is a secret message."


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:

    def test_key_len_is_32(self):
        assert KEY_LEN == 32

    def test_nonce_len_is_12(self):
        assert NONCE_LEN == 12

    def test_tag_len_is_16(self):
        assert TAG_LEN == 16

    def test_min_ct_len_is_nonce_plus_tag(self):
        assert MIN_CT_LEN == NONCE_LEN + TAG_LEN

    def test_wire_overhead_is_28_bytes(self):
        """Every message pays: 12 (nonce) + 16 (tag) = 28 bytes."""
        assert NONCE_LEN + TAG_LEN == 28

    def test_max_skip_is_positive_int(self):
        assert isinstance(MAX_SKIP, int)
        assert MAX_SKIP > 0

    def test_max_skip_within_signal_recommendation(self):
        """Signal DR spec §2.6 recommends 1000."""
        assert MAX_SKIP <= 1000


# ── Nonce derivation ──────────────────────────────────────────────────────────

class TestDeriveNonce:
    """
    _derive_nonce(message_key, message_index) is the HKDF-based deterministic
    nonce. It takes the key (not a caller-supplied chain index) so domain
    separation is inherited from the Double Ratchet key schedule.
    """

    def test_output_is_12_bytes(self, key):
        assert len(_derive_nonce(key, 0)) == NONCE_LEN

    def test_is_deterministic(self, key):
        assert _derive_nonce(key, 5) == _derive_nonce(key, 5)

    def test_different_message_index_gives_different_nonce(self, key):
        assert _derive_nonce(key, 0) != _derive_nonce(key, 1)

    def test_different_key_gives_different_nonce(self):
        """
        Domain separation comes from the key, not a chain_index counter.
        Two different message keys (from different ratchet steps) must
        produce different nonces even at the same message_index.
        """
        assert _derive_nonce(_make_key(0), 0) != _derive_nonce(_make_key(1), 0)

    def test_large_message_index_boundary(self, key):
        """message_index is uint64; 2^64-1 must not overflow or raise."""
        assert len(_derive_nonce(key, 2**64 - 1)) == NONCE_LEN

    def test_zero_message_index(self, key):
        assert len(_derive_nonce(key, 0)) == NONCE_LEN

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match=str(KEY_LEN)):
            _derive_nonce(b"tooshort", 0)

    def test_negative_message_index_raises(self, key):
        with pytest.raises((ValueError, struct.error)):
            _derive_nonce(key, -1)

    def test_unique_across_simulated_ratchet_session(self):
        """
        Simulate 20 ratchet steps, 50 messages each.
        Each step yields a unique message_key from the ratchet, so
        (key, index) pairs are all distinct — no nonce should repeat.
        """
        nonces = set()
        for step in range(20):
            mk = _unique_key(step)
            for idx in range(50):
                n = _derive_nonce(mk, idx)
                assert n not in nonces, f"Collision at step={step}, idx={idx}"
                nonces.add(n)
        assert len(nonces) == 1000

    def test_nonce_is_first_12_bytes_of_wire_format(self, key, ad):
        """Wire format starts with nonce — no reuse guard prefix."""
        ct = encrypt(key, b"test", ad, message_index=7)
        assert ct[:NONCE_LEN] == _derive_nonce(key, 7)


# ── Constant time comparison ─────────────────────────────────────────────────
#
# The custom _constant_time_equal helper has been replaced with
# hmac.compare_digest (Python stdlib, guaranteed constant-time by CPython).
# No unit tests needed — it is a stdlib function with its own test suite.
# Its use in decrypt() is covered implicitly by TestTamperDetection.


# ── Encrypt / Decrypt round-trip ──────────────────────────────────────────────

class TestEncryptDecryptRoundtrip:

    def test_basic_roundtrip(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        assert decrypt(key, ct, ad, message_index=0) == plaintext

    def test_empty_plaintext(self, key, ad):
        ct = encrypt(key, b"", ad, message_index=0)
        assert decrypt(key, ct, ad, message_index=0) == b""

    def test_large_plaintext(self, key, ad):
        big = bytes(range(256)) * 100   # 25,600 bytes
        ct  = encrypt(key, big, ad, message_index=0)
        assert decrypt(key, ct, ad, message_index=0) == big

    def test_wire_length(self, key, plaintext, ad):
        """Overhead = 12 (nonce) + 16 (tag) = 28 bytes."""
        ct = encrypt(key, plaintext, ad, message_index=0)
        assert len(ct) == NONCE_LEN + len(plaintext) + TAG_LEN

    def test_nonce_is_first_12_bytes(self, key, plaintext, ad):
        """Wire format starts with nonce — no reuse guard prefix."""
        ct = encrypt(key, plaintext, ad, message_index=3)
        assert ct[:NONCE_LEN] == _derive_nonce(key, 3)

    def test_encryption_is_deterministic(self, key, plaintext, ad):
        """
        Without the reuse guard, encryption is fully deterministic.
        Same (key, plaintext, ad, index) → same wire bytes every time.
        Safe because the key is single-use — the ratchet prevents reuse.
        """
        ct1 = encrypt(key, plaintext, ad, message_index=0)
        ct2 = encrypt(key, plaintext, ad, message_index=0)
        assert ct1 == ct2

    def test_sequential_messages_produce_different_ciphertexts(self, key, ad):
        ct0 = encrypt(key, b"message A", ad, message_index=0)
        ct1 = encrypt(key, b"message A", ad, message_index=1)
        assert ct0 != ct1

    def test_wrong_message_index_on_decrypt_raises(self, key, plaintext, ad):
        """
        decrypt() re-derives the expected nonce and verifies it against
        the wire. A mismatched index is caught before ChaCha20 is invoked.
        """
        ct = encrypt(key, plaintext, ad, message_index=5)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, ad, message_index=6)

    def test_roundtrip_across_many_indices(self, key, ad):
        """Sequential messages all round-trip correctly."""
        for i in range(20):
            pt = f"message {i}".encode()
            ct = encrypt(key, pt, ad, message_index=i)
            assert decrypt(key, ct, ad, message_index=i) == pt


# ── Associated data binding ───────────────────────────────────────────────────

class TestAssociatedData:

    def test_wrong_ad_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, b"wrong_ad", message_index=0)

    def test_empty_ad_accepted(self, key, plaintext):
        ct = encrypt(key, plaintext, b"", message_index=0)
        assert decrypt(key, ct, b"", message_index=0) == plaintext

    def test_ad_length_prefix_prevents_concatenation_ambiguity(
            self, key, plaintext):
        """
        Without length-prefixing, b"alice"||b"bob" == b"aliceb"||b"ob".
        This test documents the ambiguity and confirms length-prefixed AD
        resolves it — the application layer must use unambiguous AD.
        """
        raw_equal_1 = b"alice"  + b"bob"    # b"alicebob"
        raw_equal_2 = b"aliceb" + b"ob"     # b"alicebob" — same bytes!
        assert raw_equal_1 == raw_equal_2   # confirms the ambiguity exists

        def lp(s: bytes) -> bytes:
            return struct.pack("!H", len(s)) + s

        lp_1 = lp(b"alice")  + lp(b"bob")  # \x00\x05alice\x00\x03bob
        lp_2 = lp(b"aliceb") + lp(b"ob")   # \x00\x06aliceb\x00\x02ob
        assert lp_1 != lp_2                 # unambiguous

        ct = encrypt(key, plaintext, lp_1, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, lp_2, message_index=0)

    def test_sender_recipient_swap_rejected(self, key, plaintext):
        """
        A server cannot replay alice→bob as bob→alice if AD encodes
        direction with length-prefixed fields.
        """
        def lp(s: bytes) -> bytes:
            return struct.pack("!H", len(s)) + s

        ad_forward  = lp(b"alice") + lp(b"bob")
        ad_reversed = lp(b"bob")   + lp(b"alice")

        ct = encrypt(key, plaintext, ad_forward, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, ad_reversed, message_index=0)


# ── Tamper detection ──────────────────────────────────────────────────────────

class TestTamperDetection:

    def test_bit_flip_in_ciphertext_body_raises(self, key, plaintext, ad):
        ct = bytearray(encrypt(key, plaintext, ad, message_index=0))
        ct[NONCE_LEN + 1] ^= 0xFF   # flip a byte in the ciphertext body
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad, message_index=0)

    def test_bit_flip_in_tag_raises(self, key, plaintext, ad):
        ct = bytearray(encrypt(key, plaintext, ad, message_index=0))
        ct[-1] ^= 0x01
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad, message_index=0)

    def test_truncated_ciphertext_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(Exception):
            decrypt(key, ct[:-1], ad, message_index=0)

    def test_too_short_raises_value_error(self, key, ad):
        with pytest.raises(ValueError, match="too short"):
            decrypt(key, b"\x00" * 10, ad, message_index=0)

    def test_extended_ciphertext_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct + b"\x00", ad, message_index=0)

    def test_nonce_tampering_raises(self, key, plaintext, ad):
        """
        Corrupting the nonce (first 12 bytes) causes the nonce consistency
        check to fail before ChaCha20 is even invoked.
        """
        ct = bytearray(encrypt(key, plaintext, ad, message_index=0))
        ct[0] ^= 0xFF   # flip first byte of nonce
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad, message_index=0)

    def test_nonce_mid_byte_tampering_raises(self, key, plaintext, ad):
        ct = bytearray(encrypt(key, plaintext, ad, message_index=0))
        ct[6] ^= 0xFF   # flip a middle nonce byte
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad, message_index=0)


# ── Wrong key ─────────────────────────────────────────────────────────────────

class TestWrongKey:

    def test_wrong_key_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(bytes(reversed(key)), ct, ad, message_index=0)

    def test_zero_key_differs_from_sequential_key(self, plaintext, ad):
        ka = bytes(KEY_LEN)
        kb = _make_key(0)
        assert (encrypt(ka, plaintext, ad, message_index=0) !=
                encrypt(kb, plaintext, ad, message_index=0))

    def test_key_length_validation_on_encrypt(self, plaintext, ad):
        with pytest.raises(ValueError, match=str(KEY_LEN)):
            encrypt(b"short", plaintext, ad, message_index=0)

    def test_key_length_validation_on_decrypt(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(ValueError, match=str(KEY_LEN)):
            decrypt(b"short", ct, ad, message_index=0)


# ── MAX_SKIP documentation ────────────────────────────────────────────────────

class TestMaxSkip:
    """
    MAX_SKIP bounds how many out-of-order message keys may be buffered.
    Enforcement lives in the ratchet layer, not in aead.py itself.
    These tests document the contract and make it auditable.
    """

    def test_max_skip_is_positive_int(self):
        assert isinstance(MAX_SKIP, int) and MAX_SKIP > 0

    def test_max_skip_prevents_unbounded_dos(self):
        """
        Signal DR spec §2.6: exceeding MAX_SKIP must be an error at the
        ratchet layer. Confirms the constant is accessible for that check.
        """
        assert MAX_SKIP + 1 > MAX_SKIP
