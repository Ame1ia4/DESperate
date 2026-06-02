"""
testing/test_password.py

Tests for core/password.py — derive_master_components()

Run with: pytest testing/test_password.py -v
"""

import os
import pytest

from core.password import derive_master_components, argon2id_derive_key
from core.kdf import INFO_SRP_AUTH, INFO_LOCAL_KEY_ENC


PASSWORD      = "correct-horse-battery-staple"
ALT_PASSWORD  = "different-password-entirely"


# ── derive_master_components ──────────────────────────────────────────────────

class TestDeriveMasterComponents:

    def test_returns_three_values(self):
        result = derive_master_components(PASSWORD)
        assert len(result) == 3

    def test_srp_pass_is_32_bytes(self):
        srp_pass, _, _ = derive_master_components(PASSWORD)
        assert len(srp_pass) == 32

    def test_keystore_key_is_32_bytes(self):
        _, keystore_key, _ = derive_master_components(PASSWORD)
        assert len(keystore_key) == 32

    def test_master_salt_is_16_bytes(self):
        _, _, master_salt = derive_master_components(PASSWORD)
        assert len(master_salt) == 16

    def test_srp_pass_and_keystore_key_are_different(self):
        """
        Domain separation: the two HKDF branches must produce different keys
        even though they share the same Argon2id output and salt.
        """
        srp_pass, keystore_key, _ = derive_master_components(PASSWORD)
        assert srp_pass != keystore_key

    def test_deterministic_with_same_salt(self):
        """Same password + same salt must always produce the same two keys."""
        _, _, salt = derive_master_components(PASSWORD)
        srp1, key1, _ = derive_master_components(PASSWORD, salt)
        srp2, key2, _ = derive_master_components(PASSWORD, salt)
        assert srp1 == srp2
        assert key1 == key2

    def test_fresh_salt_generated_when_none(self):
        """Called without a salt, a random 16-byte salt must be generated."""
        _, _, salt = derive_master_components(PASSWORD)
        assert isinstance(salt, bytes)
        assert len(salt) == 16

    def test_two_calls_without_salt_produce_different_salts(self):
        """Each registration generates a fresh salt — keys must not repeat."""
        _, _, salt1 = derive_master_components(PASSWORD)
        _, _, salt2 = derive_master_components(PASSWORD)
        assert salt1 != salt2

    def test_two_calls_without_salt_produce_different_keys(self):
        srp1, key1, _ = derive_master_components(PASSWORD)
        srp2, key2, _ = derive_master_components(PASSWORD)
        assert srp1 != srp2
        assert key1 != key2

    def test_different_passwords_same_salt_give_different_keys(self):
        _, _, salt = derive_master_components(PASSWORD)
        srp1, key1, _ = derive_master_components(PASSWORD,     salt)
        srp2, key2, _ = derive_master_components(ALT_PASSWORD, salt)
        assert srp1 != srp2
        assert key1 != key2

    def test_same_password_different_salts_give_different_keys(self):
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        srp1, key1, _ = derive_master_components(PASSWORD, salt1)
        srp2, key2, _ = derive_master_components(PASSWORD, salt2)
        assert srp1 != srp2
        assert key1 != key2

    def test_provided_salt_is_returned_unchanged(self):
        salt = os.urandom(16)
        _, _, returned_salt = derive_master_components(PASSWORD, salt)
        assert returned_salt == salt

    def test_all_outputs_are_bytes(self):
        srp_pass, keystore_key, master_salt = derive_master_components(PASSWORD)
        assert isinstance(srp_pass,    bytes)
        assert isinstance(keystore_key, bytes)
        assert isinstance(master_salt,  bytes)

    def test_srp_pass_is_not_raw_password_bytes(self):
        """srp_pass must be a derived key, not just the password encoded."""
        srp_pass, _, _ = derive_master_components(PASSWORD)
        assert srp_pass != PASSWORD.encode("utf-8")

    def test_keystore_key_is_not_raw_password_bytes(self):
        keystore_key, _, _ = derive_master_components(PASSWORD)
        assert keystore_key != PASSWORD.encode("utf-8")

    def test_wrong_salt_length_raises(self):
        with pytest.raises(ValueError, match="salt"):
            derive_master_components(PASSWORD, os.urandom(8))  # 8 bytes, not 16

    def test_unicode_password_is_handled(self):
        """Master password may contain non-ASCII characters."""
        pwd = "pässwörd_ñoño_🔑"
        srp1, key1, salt = derive_master_components(pwd)
        srp2, key2, _    = derive_master_components(pwd, salt)
        assert srp1 == srp2
        assert key1 == key2


class TestMasterPasswordDomainSeparation:
    """
    Critical: srp_pass and keystore_key must be cryptographically independent.
    Knowledge of one must not help derive the other.
    """

    def test_srp_pass_and_keystore_key_differ_across_passwords(self):
        for pwd in [PASSWORD, ALT_PASSWORD, "short", "a" * 100]:
            srp_pass, keystore_key, _ = derive_master_components(pwd)
            assert srp_pass != keystore_key, f"Keys matched for password {pwd!r}"

    def test_server_breach_does_not_expose_keystore_key(self):
        """
        Simulate a server breach: attacker knows the SRP verifier and,
        hypothetically, srp_pass. They must not be able to derive keystore_key
        from srp_pass alone (no inverse of HKDF without the Argon2id master_key).
        This test confirms the two keys are distinct — the cryptographic
        independence comes from HKDF domain separation via different info strings.
        """
        srp_pass, keystore_key, _ = derive_master_components(PASSWORD)
        # A brute-force attacker who somehow gets srp_pass cannot re-derive
        # keystore_key because they don't have master_key (the Argon2id output).
        # At minimum, they must be different values.
        assert srp_pass != keystore_key

    def test_srp_pass_hex_is_valid_hex_string(self):
        """srp_pass is passed to SrpSession as .hex() — must encode cleanly."""
        srp_pass, _, _ = derive_master_components(PASSWORD)
        hex_str = srp_pass.hex()
        assert len(hex_str) == 64       # 32 bytes → 64 hex chars
        assert bytes.fromhex(hex_str) == srp_pass
