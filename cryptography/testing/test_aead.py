"""
Unit tests for core/aead.py
ChaCha20-Poly1305 encryption with counter-based nonce derivation.

Run with: pytest test_aead.py -v
"""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from core.aead import _derive_nonce, encrypt, decrypt



# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def key():
    """A valid 32-byte ChaCha20-Poly1305 key."""
    return bytes(range(32))  # deterministic, not for production use

@pytest.fixture
def ad():
    """Typical associated data: sender_id || recipient_id || session_id."""
    return b"alice" + b"bob" + b"session-001"

@pytest.fixture
def plaintext():
    return b"Hello, Bob. This is a secret message."


# ── Nonce derivation ─────────────────────────────────────────────────────────

class TestNonceDerivation:

    def test_nonce_is_12_bytes(self):
        nonce = _derive_nonce(0, 0)
        assert len(nonce) == 12

    def test_nonce_is_deterministic(self):
        assert _derive_nonce(1, 5) == _derive_nonce(1, 5)

    def test_different_chain_index_gives_different_nonce(self):
        assert _derive_nonce(0, 0) != _derive_nonce(1, 0)

    def test_different_message_index_gives_different_nonce(self):
        assert _derive_nonce(0, 0) != _derive_nonce(0, 1)

    def test_nonce_unique_across_chain_and_message(self):
        """
        Core uniqueness guarantee: no two (chain, message) pairs
        produce the same nonce, even when indices are transposed.
        e.g. (chain=1, msg=1) != (chain=0, msg=1)
        This matters for out-of-order delivery across concurrent chains.
        """
        assert _derive_nonce(1, 1) != _derive_nonce(0, 1)

    def test_nonce_encodes_chain_index_little_endian(self):
        nonce = _derive_nonce(chain_index=1, message_index=0)
        assert nonce[:4] == (1).to_bytes(4, "little")

    def test_nonce_encodes_message_index_little_endian(self):
        nonce = _derive_nonce(chain_index=0, message_index=1)
        assert nonce[4:] == (1).to_bytes(8, "little")

    def test_large_indices_do_not_overflow(self):
        """Boundary: message_index up to 2^64-1, chain_index up to 2^32-1."""
        nonce = _derive_nonce(chain_index=0xFFFFFFFF, message_index=0xFFFFFFFFFFFFFFFF)
        assert len(nonce) == 12

    def test_zero_indices(self):
        nonce = _derive_nonce(0, 0)
        assert nonce == b'\x00' * 12


# ── Encrypt / Decrypt roundtrip ──────────────────────────────────────────────

class TestEncryptDecryptRoundtrip:

    def test_basic_roundtrip(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        recovered = decrypt(key, ct, ad)
        assert recovered == plaintext

    def test_roundtrip_with_empty_plaintext(self, key, ad):
        ct = encrypt(key, b"", ad, chain_index=0, message_index=0)
        assert decrypt(key, ct, ad) == b""

    def test_roundtrip_with_large_plaintext(self, key, ad):
        big = bytes(range(256)) * 100   # 25,600 bytes
        ct = encrypt(key, big, ad, chain_index=0, message_index=0)
        assert decrypt(key, ct, ad) == big

    def test_ciphertext_is_longer_than_plaintext(self, key, plaintext, ad):
        """Ciphertext = 12-byte nonce + plaintext + 16-byte Poly1305 tag."""
        ct = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        assert len(ct) == 12 + len(plaintext) + 16

    def test_nonce_prepended_to_ciphertext(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, chain_index=3, message_index=7)
        expected_nonce = _derive_nonce(3, 7)
        assert ct[:12] == expected_nonce

    def test_different_messages_same_key_produce_different_ciphertexts(
            self, key, ad):
        ct1 = encrypt(key, b"message one", ad, chain_index=0, message_index=0)
        ct2 = encrypt(key, b"message two", ad, chain_index=0, message_index=1)
        assert ct1 != ct2

    def test_same_plaintext_different_indices_produce_different_ciphertexts(
            self, key, plaintext, ad):
        """
        Identical plaintext under different (chain, message) pairs must
        produce different ciphertexts — different nonces guarantee this.
        """
        ct1 = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        ct2 = encrypt(key, plaintext, ad, chain_index=0, message_index=1)
        assert ct1 != ct2


# ── Associated data binding ──────────────────────────────────────────────────

class TestAssociatedData:

    def test_wrong_ad_raises_on_decrypt(self, key, plaintext, ad):
        """
        Poly1305 tag covers the AD — any change to AD must be rejected.
        This is what binds sender_id/recipient_id/session_id to the ciphertext.
        """
        ct = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, b"wrong_associated_data")

    def test_empty_ad_is_accepted(self, key, plaintext):
        ct = encrypt(key, plaintext, b"", chain_index=0, message_index=0)
        assert decrypt(key, ct, b"") == plaintext

    def test_swapped_sender_recipient_in_ad_fails(self, key, plaintext):
        """
        AD = sender || recipient. Swapping them must invalidate the tag,
        preventing a server from reflecting a message back to its sender.
        """
        ad_forward  = b"alice" + b"bob"
        ad_reversed = b"bob"   + b"alice"
        ct = encrypt(key, plaintext, ad_forward, chain_index=0, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct, ad_reversed)


# ── Tamper detection ─────────────────────────────────────────────────────────

class TestTamperDetection:

    def test_bit_flip_in_ciphertext_body_raises(self, key, plaintext, ad):
        ct = bytearray(encrypt(key, plaintext, ad, chain_index=0, message_index=0))
        ct[13] ^= 0xFF   # flip bits in the ciphertext body (past the nonce)
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad)

    def test_bit_flip_in_tag_raises(self, key, plaintext, ad):
        ct = bytearray(encrypt(key, plaintext, ad, chain_index=0, message_index=0))
        ct[-1] ^= 0x01   # flip a bit in the Poly1305 tag
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad)

    def test_truncated_ciphertext_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        with pytest.raises(Exception):
            decrypt(key, ct[:-1], ad)   # remove last byte of tag

    def test_extended_ciphertext_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        with pytest.raises(InvalidTag):
            decrypt(key, ct + b"\x00", ad)

    def test_nonce_tampering_raises(self, key, plaintext, ad):
        ct = bytearray(encrypt(key, plaintext, ad, chain_index=0, message_index=0))
        ct[0] ^= 0xFF    # corrupt the nonce prefix
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct), ad)


# ── Wrong key ────────────────────────────────────────────────────────────────

class TestWrongKey:

    def test_wrong_key_raises(self, key, plaintext, ad):
        ct = encrypt(key, plaintext, ad, chain_index=0, message_index=0)
        wrong_key = bytes(reversed(key))
        with pytest.raises(InvalidTag):
            decrypt(wrong_key, ct, ad)

    def test_all_zero_key_different_from_sequential_key(self, plaintext, ad):
        key_a = bytes(32)
        key_b = bytes(range(32))
        ct_a = encrypt(key_a, plaintext, ad, chain_index=0, message_index=0)
        ct_b = encrypt(key_b, plaintext, ad, chain_index=0, message_index=0)
        assert ct_a != ct_b


# ── Nonce uniqueness across concurrent chains ────────────────────────────────

class TestCrossChainUniqueness:

    def test_all_nonces_unique_in_session(self):
        """
        Simulate a session with 10 chain steps, 10 messages each.
        Every (chain_index, message_index) pair must produce a unique nonce.
        This is the core defence against cross-chain nonce reuse.
        """
        nonces = set()
        for chain in range(10):
            for msg in range(10):
                n = _derive_nonce(chain, msg)
                assert n not in nonces, (
                    f"Nonce collision at chain={chain}, msg={msg}"
                )
                nonces.add(n)
        assert len(nonces) == 100

    def test_same_plaintext_different_chains_different_ciphertexts(
            self, key, plaintext, ad):
        """
        Even with identical plaintext and key, different chain positions
        must produce different ciphertexts.
        """
        ct_chain_0 = encrypt(key, plaintext, ad, chain_index=0, message_index=5)
        ct_chain_1 = encrypt(key, plaintext, ad, chain_index=1, message_index=5)
        assert ct_chain_0 != ct_chain_1
