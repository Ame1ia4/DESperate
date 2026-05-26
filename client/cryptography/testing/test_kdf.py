"""
tests/test_kdf.py

Unit tests for core/kdf.py

Run with: pytest tests/test_kdf.py -v
"""

import os
import pytest

from core.kdf import (
    # HKDF
    hkdf_derive,
    hkdf_derive_many,
    # Info strings
    INFO_PQXDH_SK,
    INFO_ROOT_KDF,
    INFO_CHAIN_KDF,
    INFO_HEADER_KEY,
    INFO_LOCAL_KEY_ENC,
    INFO_LOCAL_KEY_MASTER,
    # Argon2id
    argon2id_hash,
    argon2id_verify,
    argon2id_derive_key,
    # Constants
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
    ARGON2_SALT_LEN,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ikm():
    return os.urandom(32)

@pytest.fixture
def salt():
    return os.urandom(32)


# ── Argon2id parameter compliance ────────────────────────────────────────────

class TestArgon2idParameters:
    """
    OWASP Password Storage Cheat Sheet requires Argon2id with at minimum:
      time_cost >= 3, memory_cost >= 64MB, parallelism >= 4
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    """

    def test_time_cost_meets_owasp_minimum(self):
        assert ARGON2_TIME_COST >= 3

    def test_memory_cost_meets_owasp_minimum(self):
        """64 MB = 65536 KiB."""
        assert ARGON2_MEMORY_COST >= 65536

    def test_parallelism_meets_owasp_minimum(self):
        assert ARGON2_PARALLELISM >= 4

    def test_hash_length_is_32_bytes(self):
        assert ARGON2_HASH_LEN == 32

    def test_salt_length_is_16_bytes(self):
        assert ARGON2_SALT_LEN == 16


# ── Domain separation ─────────────────────────────────────────────────────────

class TestDomainSeparation:
    """
    Core security requirement: different info strings must produce different
    keys even with identical IKM and salt. Without this, a key derived for
    one purpose could be used in another context.
    """

    def test_all_info_strings_are_distinct(self):
        info_strings = [
            INFO_PQXDH_SK,
            INFO_ROOT_KDF,
            INFO_CHAIN_KDF,
            INFO_HEADER_KEY,
            INFO_LOCAL_KEY_ENC,
            INFO_LOCAL_KEY_MASTER,
        ]
        assert len(set(info_strings)) == len(info_strings)

    def test_different_info_produces_different_keys(self, ikm, salt):
        """Same IKM + salt, different info → different output keys."""
        key_pqxdh  = hkdf_derive(ikm, salt, INFO_PQXDH_SK)
        key_root   = hkdf_derive(ikm, salt, INFO_ROOT_KDF)
        key_chain  = hkdf_derive(ikm, salt, INFO_CHAIN_KDF)
        key_header = hkdf_derive(ikm, salt, INFO_HEADER_KEY)
        key_local  = hkdf_derive(ikm, salt, INFO_LOCAL_KEY_ENC)

        keys = [key_pqxdh, key_root, key_chain, key_header, key_local]
        assert len(set(keys)) == len(keys), "Two info strings produced the same key"

    def test_pqxdh_and_local_key_enc_are_independent(self, ikm, salt):
        """
        Critical: PQXDH shared secret derivation and local key encryption
        must be cryptographically independent. If they produced the same key,
        a server learning the session key could derive the local key.
        """
        k1 = hkdf_derive(ikm, salt, INFO_PQXDH_SK)
        k2 = hkdf_derive(ikm, salt, INFO_LOCAL_KEY_ENC)
        assert k1 != k2

    def test_all_info_strings_are_bytes(self):
        for info in [
            INFO_PQXDH_SK, INFO_ROOT_KDF, INFO_CHAIN_KDF,
            INFO_HEADER_KEY, INFO_LOCAL_KEY_ENC, INFO_LOCAL_KEY_MASTER,
        ]:
            assert isinstance(info, bytes)

    def test_all_info_strings_are_nonempty(self):
        for info in [
            INFO_PQXDH_SK, INFO_ROOT_KDF, INFO_CHAIN_KDF,
            INFO_HEADER_KEY, INFO_LOCAL_KEY_ENC, INFO_LOCAL_KEY_MASTER,
        ]:
            assert len(info) > 0


# ── hkdf_derive ───────────────────────────────────────────────────────────────

class TestHKDFDerive:

    def test_output_is_32_bytes_by_default(self, ikm, salt):
        key = hkdf_derive(ikm, salt, INFO_ROOT_KDF)
        assert len(key) == 32

    def test_output_length_is_respected(self, ikm, salt):
        for length in [16, 32, 48, 64]:
            key = hkdf_derive(ikm, salt, INFO_ROOT_KDF, length=length)
            assert len(key) == length

    def test_is_deterministic(self, ikm, salt):
        k1 = hkdf_derive(ikm, salt, INFO_ROOT_KDF)
        k2 = hkdf_derive(ikm, salt, INFO_ROOT_KDF)
        assert k1 == k2

    def test_different_ikm_gives_different_key(self, salt):
        k1 = hkdf_derive(os.urandom(32), salt, INFO_ROOT_KDF)
        k2 = hkdf_derive(os.urandom(32), salt, INFO_ROOT_KDF)
        assert k1 != k2

    def test_different_salt_gives_different_key(self, ikm):
        k1 = hkdf_derive(ikm, os.urandom(32), INFO_ROOT_KDF)
        k2 = hkdf_derive(ikm, os.urandom(32), INFO_ROOT_KDF)
        assert k1 != k2

    def test_output_is_not_ikm(self, ikm, salt):
        """Sanity: HKDF must transform its input, not echo it."""
        key = hkdf_derive(ikm, salt, INFO_ROOT_KDF)
        assert key != ikm

    def test_empty_ikm_raises(self, salt):
        with pytest.raises(ValueError, match="ikm"):
            hkdf_derive(b"", salt, INFO_ROOT_KDF)

    def test_empty_salt_raises(self, ikm):
        with pytest.raises(ValueError, match="salt"):
            hkdf_derive(ikm, b"", INFO_ROOT_KDF)

    def test_empty_info_raises(self, ikm, salt):
        """Enforce use of INFO_* constants — empty info disables domain separation."""
        with pytest.raises(ValueError, match="info"):
            hkdf_derive(ikm, salt, b"")

    def test_zero_length_raises(self, ikm, salt):
        with pytest.raises(ValueError, match="length"):
            hkdf_derive(ikm, salt, INFO_ROOT_KDF, length=0)

    def test_negative_length_raises(self, ikm, salt):
        with pytest.raises(ValueError, match="length"):
            hkdf_derive(ikm, salt, INFO_ROOT_KDF, length=-1)

    def test_root_kdf_produces_independent_keys_for_different_ratchet_steps(self):
        """
        Simulate two consecutive DH ratchet steps. Each step uses a different
        DH output as IKM and the previous root key as salt. The resulting
        root keys and chain keys must all be distinct.
        """
        rk   = os.urandom(32)   # initial root key
        keys = set()

        for _ in range(5):
            dh_out    = os.urandom(32)
            rk, ck    = hkdf_derive_many(dh_out, rk, INFO_ROOT_KDF, [32, 32])
            keys.add(rk)
            keys.add(ck)

        assert len(keys) == 10   # all 10 keys (5 rk + 5 ck) must be unique


# ── hkdf_derive_many ──────────────────────────────────────────────────────────

class TestHKDFDeriveMany:

    def test_returns_correct_number_of_keys(self, ikm, salt):
        keys = hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [32, 32])
        assert len(keys) == 2

    def test_root_kdf_returns_root_and_chain_keys(self, ikm, salt):
        """Primary use case: DR root KDF produces root key + chain key."""
        root_key, chain_key = hkdf_derive_many(
            ikm, salt, INFO_ROOT_KDF, [32, 32]
        )
        assert len(root_key)  == 32
        assert len(chain_key) == 32
        assert root_key != chain_key

    def test_keys_are_deterministic(self, ikm, salt):
        keys1 = hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [32, 32])
        keys2 = hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [32, 32])
        assert keys1 == keys2

    def test_different_lengths_respected(self, ikm, salt):
        keys = hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [16, 32, 48])
        assert [len(k) for k in keys] == [16, 32, 48]

    def test_keys_are_contiguous_slices_of_same_hkdf_output(self, ikm, salt):
        """
        Combined single-key derivation must equal concatenation of multi-key
        derivation. Ensures hkdf_derive_many is just a split of one HKDF call.
        """
        combined = hkdf_derive(ikm, salt, INFO_ROOT_KDF, length=64)
        k1, k2   = hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [32, 32])
        assert k1 + k2 == combined

    def test_empty_lengths_raises(self, ikm, salt):
        with pytest.raises(ValueError):
            hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [])

    def test_zero_length_entry_raises(self, ikm, salt):
        with pytest.raises(ValueError):
            hkdf_derive_many(ikm, salt, INFO_ROOT_KDF, [32, 0])


# ── argon2id_hash / argon2id_verify ──────────────────────────────────────────

class TestArgon2idServerSide:

    def test_hash_is_string(self):
        h = argon2id_hash("password123")
        assert isinstance(h, str)

    def test_hash_contains_argon2id_identifier(self):
        """Encoded string must identify the algorithm for future verification."""
        h = argon2id_hash("password123")
        assert "argon2id" in h

    def test_hash_contains_correct_parameters(self):
        """Parameters must be embedded in the hash string for verifiability."""
        h = argon2id_hash("password123")
        assert f"m={ARGON2_MEMORY_COST}" in h
        assert f"t={ARGON2_TIME_COST}"   in h
        assert f"p={ARGON2_PARALLELISM}" in h

    def test_two_hashes_of_same_password_differ(self):
        """Each call generates a fresh random salt — hashes must not repeat."""
        h1 = argon2id_hash("password123")
        h2 = argon2id_hash("password123")
        assert h1 != h2

    def test_verify_correct_password_returns_true(self):
        h = argon2id_hash("correct_password")
        assert argon2id_verify(h, "correct_password") is True

    def test_verify_wrong_password_returns_false(self):
        h = argon2id_hash("correct_password")
        assert argon2id_verify(h, "wrong_password") is False

    def test_verify_empty_password_returns_false(self):
        h = argon2id_hash("correct_password")
        assert argon2id_verify(h, "") is False

    def test_verify_does_not_raise_on_mismatch(self):
        """Authentication failures must return False, never raise."""
        h = argon2id_hash("password")
        result = argon2id_verify(h, "wrong")
        assert result is False   # no exception

    def test_different_passwords_produce_different_hashes(self):
        h1 = argon2id_hash("password_one")
        h2 = argon2id_hash("password_two")
        assert h1 != h2

    def test_unicode_password_is_handled(self):
        pwd = "pässwörd_ñoño_🔑"
        h   = argon2id_hash(pwd)
        assert argon2id_verify(h, pwd)


# ── argon2id_derive_key ───────────────────────────────────────────────────────

class TestArgon2idLocalKeyDerivation:

    def test_returns_32_byte_key(self):
        key, _ = argon2id_derive_key("passphrase")
        assert len(key) == 32

    def test_returns_16_byte_salt(self):
        _, salt = argon2id_derive_key("passphrase")
        assert len(salt) == 16

    def test_is_deterministic_with_same_salt(self):
        _, salt = argon2id_derive_key("passphrase")
        k1, _  = argon2id_derive_key("passphrase", salt)
        k2, _  = argon2id_derive_key("passphrase", salt)
        assert k1 == k2

    def test_different_salts_give_different_keys(self):
        k1, _ = argon2id_derive_key("passphrase", os.urandom(16))
        k2, _ = argon2id_derive_key("passphrase", os.urandom(16))
        assert k1 != k2

    def test_different_passphrases_give_different_keys(self):
        salt   = os.urandom(16)
        k1, _  = argon2id_derive_key("passphrase_one", salt)
        k2, _  = argon2id_derive_key("passphrase_two", salt)
        assert k1 != k2

    def test_provided_salt_is_returned_unchanged(self):
        salt      = os.urandom(16)
        _, out_salt = argon2id_derive_key("passphrase", salt)
        assert out_salt == salt

    def test_wrong_salt_length_raises(self):
        with pytest.raises(ValueError, match="salt"):
            argon2id_derive_key("passphrase", os.urandom(8))

    def test_local_key_is_independent_of_server_hash(self):
        """
        Critical: the local key derivation and server password hash must be
        independent. Even if an attacker learns the server-side Argon2id hash,
        they cannot derive the local encryption key because the salts differ.
        This test verifies the outputs are different given the same passphrase.
        """
        passphrase  = "shared_passphrase"
        server_hash = argon2id_hash(passphrase)
        local_key, local_salt = argon2id_derive_key(passphrase)

        # The server hash and local key must not be the same bytes
        assert local_key.hex() not in server_hash
        assert local_key != server_hash.encode()

    def test_local_key_fed_into_hkdf_for_encryption_key(self):
        """
        Full local key derivation pipeline: passphrase → Argon2id → HKDF.
        Verifies the two-step derivation produces a usable 32-byte key and
        that the pipeline is deterministic with the same inputs.
        """
        passphrase    = "my_local_passphrase"
        raw_key, salt = argon2id_derive_key(passphrase)

        enc_key_1 = hkdf_derive(raw_key, salt, INFO_LOCAL_KEY_ENC)
        enc_key_2 = hkdf_derive(raw_key, salt, INFO_LOCAL_KEY_ENC)

        assert len(enc_key_1) == 32
        assert enc_key_1 == enc_key_2   # deterministic
        assert enc_key_1 != raw_key     # HKDF transformed it
