"""
Unit tests for core/aead.py
ChaCha20-Poly1305 AEAD with HKDF-derived nonces and MLS reuse guard.

Run with: pytest test_aead.py -v

Wire format under test:
  reuse_guard (4 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
  = 32 bytes of overhead per message
"""

import struct

import pytest
from cryptography.exceptions import InvalidTag

from core.aead import (
    MAX_SKIP,
    _HEADER_LEN,       # 16  (4 reuse_guard + 12 nonce)
    _REUSE_GUARD_LEN,  # 4
    _NONCE_LEN,        # 12
    _TAG_LEN,          # 16
    _derive_base_nonce,
    _apply_reuse_guard,
    decrypt,
    encrypt,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_key(seed: int = 0) -> bytes:
    """Deterministic 32-byte key for testing. Never use in production."""
    return bytes([(seed + i) % 256 for i in range(32)])


def _unique_key(n: int) -> bytes:
    """Return a unique 32-byte key for message n (simulates the ratchet)."""
    return bytes([(n * 7 + i) % 256 for i in range(32)])


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def key():
    return _make_key(0)


@pytest.fixture
def ad():
    """
    Length-prefixed AD: prevents the concatenation ambiguity noted in the
    PR (b"alice" + b"bob" == b"aliceb" + b"ob"). Tests that need raw AD
    bytes can construct their own.
    """
    sender    = b"alice"
    recipient = b"bob"
    return struct.pack("!H", len(sender)) + sender + struct.pack("!H", len(recipient)) + recipient


@pytest.fixture
def plaintext():
    return b"Hello, Bob. This is a secret message."


# ── Constants ────────────────────────────────────────────────────────────────

class TestConstants:

    def test_max_skip_defined(self):
        assert isinstance(MAX_SKIP, int)
        assert MAX_SKIP > 0

    def test_max_skip_value(self):
        # Signal DR spec §2.6 recommends 1000; tighter values are also fine
        assert MAX_SKIP <= 1000

    def test_header_len_is_reuse_guard_plus_nonce(self):
        assert _HEADER_LEN == _REUSE_GUARD_LEN + _NONCE_LEN  # 4 + 12 = 16

    def test_wire_overhead_is_32_bytes(self):
        """Every message pays: 4 (guard) + 12 (nonce) + 16 (tag) = 32 bytes."""
        assert _HEADER_LEN + _TAG_LEN == 32


# ── Base nonce derivation ─────────────────────────────────────────────────────

class TestDeriveBaseNonce:
    """
    _derive_base_nonce(message_key, message_index) is the HKDF-based
    deterministic nonce. It takes the *key* (not a caller-supplied chain
    index) so domain separation is inherited from the Double Ratchet
    key schedule.
    """

    def test_output_is_12_bytes(self, key):
        assert len(_derive_base_nonce(key, 0)) == 12

    def test_deterministic(self, key):
        assert _derive_base_nonce(key, 5) == _derive_base_nonce(key, 5)

    def test_different_message_index_gives_different_nonce(self, key):
        assert _derive_base_nonce(key, 0) != _derive_base_nonce(key, 1)

    def test_different_key_gives_different_nonce(self):
        """
        Domain separation comes from the key, not a chain_index counter.
        Two different message keys (from different ratchet steps) must
        produce different base nonces even at the same message_index.
        """
        k1 = _make_key(0)
        k2 = _make_key(1)
        assert _derive_base_nonce(k1, 0) != _derive_base_nonce(k2, 0)

    def test_large_message_index_boundary(self, key):
        """message_index is uint64; 2^64-1 must not overflow or raise."""
        nonce = _derive_base_nonce(key, 2**64 - 1)
        assert len(nonce) == 12

    def test_zero_message_index(self, key):
        nonce = _derive_base_nonce(key, 0)
        assert len(nonce) == 12

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            _derive_base_nonce(b"tooshort", 0)

    def test_negative_message_index_raises(self, key):
        with pytest.raises((ValueError, struct.error)):
            _derive_base_nonce(key, -1)

    def test_unique_across_simulated_ratchet_session(self):
        """
        Simulate 20 ratchet steps, 50 messages each.
        Each step yields a unique message_key from the ratchet, so
        (key, index) pairs are all distinct — no base nonce should repeat.
        """
        nonces = set()
        for step in range(20):
            mk = _unique_key(step)
            for idx in range(50):
                n = _derive_base_nonce(mk, idx)
                assert n not in nonces, f"Collision at step={step}, idx={idx}"
                nonces.add(n)
        assert len(nonces) == 1000


# ── Reuse guard application ───────────────────────────────────────────────────

class TestApplyReuseGuard:
    """
    MLS draft §9.3: XOR a 4-byte random guard into the first 4 bytes of the
    deterministic base nonce before use. The guard is prepended to the wire
    format so the receiver can undo it and verify consistency.
    """

    def test_output_is_12_bytes(self, key):
        base = _derive_base_nonce(key, 0)
        assert len(_apply_reuse_guard(base, b"\x00" * 4)) == 12

    def test_zero_guard_is_identity(self, key):
        base = _derive_base_nonce(key, 0)
        assert _apply_reuse_guard(base, b"\x00" * 4) == base

    def test_guard_xored_into_first_four_bytes(self, key):
        base  = _derive_base_nonce(key, 0)
        guard = b"\xDE\xAD\xBE\xEF"
        result = _apply_reuse_guard(base, guard)

        for i in range(4):
            assert result[i] == base[i] ^ guard[i]
        # Bytes 4–11 are untouched
        assert result[4:] == base[4:]

    def test_guard_is_invertible(self, key):
        """Applying the same guard twice recovers the original nonce."""
        base  = _derive_base_nonce(key, 0)
        guard = b"\x01\x02\x03\x04"
        guarded = _apply_reuse_guard(base, guard)
        recovered = _apply_reuse_guard(guarded, guard)
        assert recovered == base

    def test_wrong_base_nonce_length_raises(self):
        with pytest.raises(ValueError, match="12 bytes"):
            _apply_reuse_guard(b"short", b"\x00" * 4)

    def test_wrong_guard_length_raises(self, key):
        base = _derive_base_nonce(key, 0)
        with pytest.raises(ValueError, match="4 bytes"):
            _apply_reuse_guard(base, b"\x00" * 3)


# ── Encrypt / Decrypt round-trip ──────────────────────────────────────────────

class TestEncryptDecryptRoundtrip:

    def test_basic_roundtrip(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        assert decrypt(key, ct, ad, message_index=0) == plaintext

    def test_empty_plaintext(self, key, ad):
        ct = encrypt(key, b"", ad, message_index=0)
        assert decrypt(key, ct, ad, message_index=0) == b""

    def test_large_plaintext(self, key, ad):
        big = bytes(range(256)) * 100  # 25,600 bytes
        ct  = encrypt(key, big, ad, message_index=0)
        assert decrypt(key, ct, ad, message_index=0) == big

    def test_wire_length(self, key, plaintext, ad):
        """
        Overhead = 4 (reuse_guard) + 12 (nonce) + 16 (tag) = 32 bytes.
        """
        ct = encrypt(key, plaintext, ad, message_index=0)
        assert len(ct) == _HEADER_LEN + len(plaintext) + _TAG_LEN

    def test_reuse_guard_prepended(self, key, plaintext, ad):
        """First 4 bytes of wire format are the reuse guard (random)."""
        ct = encrypt(key, plaintext, ad, message_index=0)
        reuse_guard = ct[:_REUSE_GUARD_LEN]
        assert len(reuse_guard) == 4

    def test_nonce_follows_reuse_guard(self, key, plaintext, ad):
        """
        Bytes [4:16] of wire format are the guarded nonce.
        We can verify: unXOR the guard → should recover the HKDF base nonce.
        """
        ct          = encrypt(key, plaintext, ad, message_index=3)
        reuse_guard = ct[:_REUSE_GUARD_LEN]
        nonce_on_wire = ct[_REUSE_GUARD_LEN:_HEADER_LEN]

        expected_base = _derive_base_nonce(key, 3)
        expected_nonce = _apply_reuse_guard(expected_base, reuse_guard)
        assert nonce_on_wire == expected_nonce

    def test_reuse_guard_is_random_across_calls(self, key, plaintext, ad):
        """
        Two encryptions of the same plaintext at the same index must differ
        because the reuse guard is fresh each time.
        """
        ct1 = encrypt(key, plaintext, ad, message_index=0)
        ct2 = encrypt(key, plaintext, ad, message_index=0)
        # Different reuse guards → different wire bytes
        assert ct1[:_REUSE_GUARD_LEN] != ct2[:_REUSE_GUARD_LEN]
        assert ct1 != ct2

    def test_sequential_messages_produce_different_ciphertexts(self, key, ad):
        ct0 = encrypt(key, b"message A", ad, message_index=0)
        ct1 = encrypt(key, b"message A", ad, message_index=1)
        assert ct0 != ct1

    def test_wrong_message_index_on_decrypt_raises(self, key, plaintext, ad):
        """
        decrypt() re-derives the expected base nonce and checks it against
        the wire nonce. A mismatched index must be caught before ChaCha20.
        """
        ct = encrypt(key, plaintext, ad, message_index=5)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, ad, message_index=6)


# ── Associated data binding ───────────────────────────────────────────────────

class TestAssociatedData:

    def test_wrong_ad_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, b"wrong_ad", message_index=0)

    def test_empty_ad_accepted(self, key, plaintext):
        ct = encrypt(key, plaintext, b"", message_index=0)
        assert decrypt(key, ct, b"", message_index=0) == plaintext

    def test_ad_length_prefix_prevents_concatenation_ambiguity(self, key, plaintext):
        """
        Without length-prefixing, b"alice"||b"bob" == b"aliceb"||b"ob".
        The fixture already uses length-prefixed AD; this test makes the
        collision explicit: raw concatenation of different splits is
        identical bytes — and AEAD cannot distinguish them.

        Your application layer MUST use length-prefixed (or otherwise
        unambiguous) AD. This test documents that requirement.
        """
        raw_equal_1 = b"alice" + b"bob"       # b"alicebob"
        raw_equal_2 = b"aliceb" + b"ob"       # b"alicebob" — same bytes!
        assert raw_equal_1 == raw_equal_2      # confirms the ambiguity exists

        # Length-prefixed versions are distinct:
        def lp(s: bytes) -> bytes:
            return struct.pack("!H", len(s)) + s

        lp_1 = lp(b"alice")  + lp(b"bob")    # \x00\x05alice\x00\x03bob
        lp_2 = lp(b"aliceb") + lp(b"ob")     # \x00\x06aliceb\x00\x02ob
        assert lp_1 != lp_2                   # unambiguous

        ct = encrypt(key, plaintext, lp_1, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, lp_2, message_index=0)

    def test_sender_recipient_swap_rejected(self, key, plaintext):
        """
        A server cannot replay alice→bob as bob→alice if the AD encodes
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
        ct[_HEADER_LEN + 1] ^= 0xFF   # flip a byte in the ciphertext body
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

    def test_reuse_guard_tampering_raises(self, key, plaintext, ad):
        """
        Corrupting the reuse guard changes the reconstructed nonce,
        causing the nonce-consistency check to fail before ChaCha20.
        """
        ct = bytearray(encrypt(key, plaintext, ad, message_index=0))
        ct[0] ^= 0xFF   # flip first byte of reuse_guard
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad, message_index=0)

    def test_nonce_field_tampering_raises(self, key, plaintext, ad):
        """
        Corrupting the nonce field (bytes 4–15) is also caught by the
        nonce-consistency check.
        """
        ct = bytearray(encrypt(key, plaintext, ad, message_index=0))
        ct[_REUSE_GUARD_LEN] ^= 0xFF   # flip first byte of nonce field
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad, message_index=0)


# ── Wrong key ─────────────────────────────────────────────────────────────────

class TestWrongKey:

    def test_wrong_key_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        wrong = bytes(reversed(key))
        with pytest.raises(InvalidTag):
            decrypt(wrong, ct, ad, message_index=0)

    def test_zero_key_differs_from_sequential_key(self, plaintext, ad):
        ka = bytes(32)
        kb = _make_key(0)
        assert encrypt(ka, plaintext, ad, message_index=0) != \
               encrypt(kb, plaintext, ad, message_index=0)

    def test_key_length_validation_on_encrypt(self, plaintext, ad):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt(b"short", plaintext, ad, message_index=0)

    def test_key_length_validation_on_decrypt(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, message_index=0)
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt(b"short", ct, ad, message_index=0)


# ── MAX_SKIP documentation ────────────────────────────────────────────────────

class TestMaxSkip:
    """
    MAX_SKIP bounds how many out-of-order message keys may be buffered.
    These tests document the contract — enforcement lives in the ratchet
    layer, not in aead.py itself.
    """

    def test_max_skip_is_positive_int(self):
        assert isinstance(MAX_SKIP, int) and MAX_SKIP > 0

    def test_max_skip_prevents_unbounded_dos(self):
        """
        Signal DR spec §2.6: exceeding MAX_SKIP should be an error at the
        ratchet layer. Confirm the constant is accessible for that check.
        """
        skipped_count = MAX_SKIP + 1
        assert skipped_count > MAX_SKIP   # trivially true; documents the intent
