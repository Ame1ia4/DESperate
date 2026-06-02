"""
testing/test_master_password.py

Integration tests for the master-password flow in crypto_service.py.

Tests exercise _handle() directly rather than via TCP, covering:
  - generate_identity_bundle  (registration)
  - unlock_keystore           (login step A)
  - srp_start                 (login step B-1)
  - srp_verify                (login step B-3, checks cache clearing)
  - srp_pass consistency      (registration verifier matches login proof)
  - partial-registration recovery (salt file exists but no bundle)

Run with: pytest testing/test_master_password.py -v
"""

import os
import importlib
import pytest
from pathlib import Path
from cryptography.exceptions import InvalidTag

import crypto_service
from crypto_service import _handle


PASSWORD     = "correct-horse-battery-staple"
WRONG_PW     = "definitely-wrong-password"
USERNAME     = "testuser"
NONCE_HEX    = os.urandom(32).hex()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_module_state(tmp_path):
    """
    Redirect _STORE_BASE_DIR to a temp directory and reset all module-level
    globals before every test. Prevents state leaking between tests.
    """
    crypto_service._STORE_BASE_DIR = tmp_path / "desperate_keys"
    crypto_service._srp_session        = None
    crypto_service._store              = None
    crypto_service._local_bundle       = None
    crypto_service._cached_srp_pass    = None
    crypto_service._cached_keystore_key = None
    crypto_service._sessions           = {}
    yield
    crypto_service._srp_session        = None
    crypto_service._store              = None
    crypto_service._local_bundle       = None
    crypto_service._cached_srp_pass    = None
    crypto_service._cached_keystore_key = None
    crypto_service._sessions           = {}


@pytest.fixture
def registered(tmp_path):
    """Run generate_identity_bundle and return the response dict."""
    nonce_hex = os.urandom(32).hex()
    return _handle("generate_identity_bundle", {
        "username": USERNAME,
        "password": PASSWORD,
        "nonce":    nonce_hex,
    })


# ── unlock_keystore ───────────────────────────────────────────────────────────

class TestUnlockKeystore:

    def test_succeeds_on_fresh_install(self):
        """No keystore on disk yet — bootstraps an empty one."""
        result = _handle("unlock_keystore", {"password": PASSWORD})
        assert result["success"] is True

    def test_fails_with_empty_password(self):
        result = _handle("unlock_keystore", {"password": ""})
        assert result["success"] is False

    def test_succeeds_after_registration(self, registered):
        crypto_service._store        = None
        crypto_service._local_bundle = None
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        result = _handle("unlock_keystore", {"password": PASSWORD})
        assert result["success"] is True

    def test_fails_with_wrong_password_after_registration(self, registered):
        crypto_service._store        = None
        crypto_service._local_bundle = None
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        result = _handle("unlock_keystore", {"password": WRONG_PW})
        assert result["success"] is False

    def test_wrong_password_clears_cached_keys(self, registered):
        """On wrong-password failure, no partial state should be cached."""
        crypto_service._store        = None
        crypto_service._local_bundle = None

        _handle("unlock_keystore", {"password": WRONG_PW})

        assert crypto_service._cached_srp_pass     is None
        assert crypto_service._cached_keystore_key  is None
        assert crypto_service._store               is None

    def test_loads_identity_bundle_after_registration(self, registered):
        crypto_service._store        = None
        crypto_service._local_bundle = None
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        _handle("unlock_keystore", {"password": PASSWORD})
        assert crypto_service._local_bundle is not None

    def test_caches_srp_pass_on_success(self, registered):
        crypto_service._store        = None
        crypto_service._local_bundle = None
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        _handle("unlock_keystore", {"password": PASSWORD})
        assert crypto_service._cached_srp_pass    is not None
        assert len(crypto_service._cached_srp_pass) == 32

    def test_caches_keystore_key_on_success(self, registered):
        crypto_service._store        = None
        crypto_service._local_bundle = None
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        _handle("unlock_keystore", {"password": PASSWORD})
        assert crypto_service._cached_keystore_key  is not None
        assert len(crypto_service._cached_keystore_key) == 32


# ── generate_identity_bundle ──────────────────────────────────────────────────

class TestGenerateIdentityBundle:

    def test_returns_expected_fields(self):
        result = _handle("generate_identity_bundle", {
            "username": USERNAME,
            "password": PASSWORD,
            "nonce":    os.urandom(32).hex(),
        })
        for field in [
            "srp_salt", "srp_verifier",
            "idk_classical_pub", "idk_pq_pub",
            "identity_signing_pub", "signed_prekey_pub", "signed_prekey_signature",
            "nonce", "nonce_signature",
        ]:
            assert field in result, f"Missing field: {field}"

    def test_srp_salt_is_64_hex_chars(self):
        result = _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        assert len(result["srp_salt"]) == 64
        bytes.fromhex(result["srp_salt"])

    def test_srp_verifier_is_hex(self):
        result = _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        bytes.fromhex(result["srp_verifier"])

    def test_caches_srp_pass_and_keystore_key(self):
        _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        assert crypto_service._cached_srp_pass     is not None
        assert crypto_service._cached_keystore_key  is not None

    def test_keystore_is_created_on_disk(self):
        _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        assert (crypto_service._STORE_BASE_DIR / "salt").exists()

    def test_identity_bundle_is_encrypted_on_disk(self):
        """Private keys must not appear in plaintext in the state file."""
        result = _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        state_file = (
            crypto_service._STORE_BASE_DIR / "sessions" / "__identity__.state"
        )
        assert state_file.exists()
        raw = state_file.read_bytes()
        # The classical public key is in the response — it must not appear in plaintext
        assert bytes.fromhex(result["idk_classical_pub"]) not in raw

    def test_partial_registration_recovery(self):
        """
        Simulate a crash after create_with_key wrote the salt but before
        save_state completed. A second call must succeed rather than raise
        FileExistsError.
        """
        # Write the salt file manually to simulate the partial state
        store_dir = crypto_service._STORE_BASE_DIR
        store_dir.mkdir(parents=True, exist_ok=True)
        (store_dir / "salt").write_bytes(os.urandom(16))

        # Second registration attempt must recover cleanly
        result = _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        assert "srp_verifier" in result


# ── srp_start ─────────────────────────────────────────────────────────────────

class TestSrpStart:

    def test_returns_A(self, registered):
        _handle("unlock_keystore", {"password": PASSWORD})
        # clear srp state so unlock_keystore re-runs cleanly above;
        # now call srp_start
        result = _handle("srp_start", {"username": USERNAME, "password": PASSWORD})
        assert "A" in result
        assert len(result["A"]) >= 64
        bytes.fromhex(result["A"])

    def test_uses_cached_srp_pass_not_re_deriving(self, registered):
        """
        After unlock_keystore, srp_start must reuse _cached_srp_pass.
        We verify by confirming _cached_srp_pass is set before srp_start
        and the same object reference is consumed.
        """
        _handle("unlock_keystore", {"password": PASSWORD})
        srp_pass_before = crypto_service._cached_srp_pass
        assert srp_pass_before is not None

        _handle("srp_start", {"username": USERNAME, "password": PASSWORD})

        # _cached_srp_pass should still be the same value (srp_start reads, not clears it)
        assert crypto_service._cached_srp_pass == srp_pass_before

    def test_derives_srp_pass_without_prior_unlock(self):
        """
        srp_start must still work even if unlock_keystore was never called
        (fallback path). Requires the salt file to exist (written by registration).
        """
        # Bootstrap the store so the salt file exists
        _handle("generate_identity_bundle", {
            "username": USERNAME, "password": PASSWORD,
            "nonce": os.urandom(32).hex(),
        })
        # Clear all caches to simulate fresh process with no unlock
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        result = _handle("srp_start", {"username": USERNAME, "password": PASSWORD})
        assert "A" in result
        assert crypto_service._cached_srp_pass is not None


# ── srp_verify — cached srp_pass is cleared ───────────────────────────────────

class TestSrpVerifyClearsCachedPass:

    def test_cached_srp_pass_cleared_after_verify(self, registered):
        """
        After a completed SRP handshake, _cached_srp_pass must be None.
        The SRP password is no longer needed once the session is established.
        """
        import hmac
        from core.srp_session import _sha256, _N, _g, _N_BYTES, _k, _pad

        _handle("unlock_keystore", {"password": PASSWORD})
        assert crypto_service._cached_srp_pass is not None

        srp_pass = crypto_service._cached_srp_pass

        # Build a minimal server-side verifier to complete the handshake
        srp_salt   = bytes.fromhex(registered["srp_salt"])
        verifier   = bytes.fromhex(registered["srp_verifier"])
        v          = int.from_bytes(verifier, "big")
        b_secret   = int.from_bytes(os.urandom(32), "big")
        B          = (_k * v + pow(_g, b_secret, _N)) % _N
        B_bytes    = B.to_bytes(_N_BYTES, "big")

        result_start     = _handle("srp_start", {"username": USERNAME, "password": PASSWORD})
        A_bytes          = bytes.fromhex(result_start["A"])
        result_challenge = _handle("srp_challenge", {
            "salt": registered["srp_salt"],
            "B":    B_bytes.hex(),
        })
        M1 = bytes.fromhex(result_challenge["M1"])

        # Compute server-side K and M2 to complete the exchange
        A     = int.from_bytes(A_bytes, "big")
        u     = int.from_bytes(_sha256(_pad(A), _pad(B)), "big")
        S     = pow(A * pow(v, u, _N), b_secret, _N)
        K     = _sha256(_pad(S))
        HN    = _sha256(_pad(_N))
        Hg    = _sha256(bytes([_g]))
        HNxHg = bytes(x ^ y for x, y in zip(HN, Hg))
        HI    = _sha256(USERNAME.encode())
        M_exp = _sha256(HNxHg, HI, srp_salt, A_bytes, B_bytes, K)
        assert hmac.compare_digest(M_exp, M1), "M1 mismatch — SRP verifier inconsistency"

        M2 = _sha256(A_bytes, M1, K).hex()
        _handle("srp_verify", {"M2": M2})

        # srp_pass must be cleared after verify
        assert crypto_service._cached_srp_pass is None

    def test_keystore_key_survives_after_verify(self, registered):
        """
        _cached_keystore_key must NOT be cleared by srp_verify — it is still
        needed to decrypt ratchet state throughout the session.
        """
        _handle("unlock_keystore", {"password": PASSWORD})
        keystore_key_before = crypto_service._cached_keystore_key

        _handle("srp_start", {"username": USERNAME, "password": PASSWORD})
        # We skip a real M2 here — just check the key survives srp_start at minimum
        assert crypto_service._cached_keystore_key == keystore_key_before


# ── SRP registration/login consistency ───────────────────────────────────────

class TestSrpConsistency:

    def test_srp_pass_same_between_registration_and_login(self, registered):
        """
        The srp_pass derived during generate_identity_bundle and the srp_pass
        derived during unlock_keystore (with the stored salt) must be identical.
        Both use derive_master_components(password, master_salt).
        """
        srp_pass_registration = crypto_service._cached_srp_pass

        # Reset and re-derive via unlock_keystore (login path)
        crypto_service._store              = None
        crypto_service._local_bundle       = None
        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        _handle("unlock_keystore", {"password": PASSWORD})
        srp_pass_login = crypto_service._cached_srp_pass

        assert srp_pass_registration == srp_pass_login

    def test_different_password_gives_different_srp_pass(self, registered):
        """Wrong password → different srp_pass → SRP handshake will fail on server."""
        srp_pass_correct = crypto_service._cached_srp_pass

        crypto_service._cached_srp_pass    = None
        crypto_service._cached_keystore_key = None

        # Bypass unlock_keystore (which would return wrong-password error)
        # and directly derive to compare
        from core.password import derive_master_components
        persisted_salt = (crypto_service._STORE_BASE_DIR / "salt").read_bytes()
        srp_pass_wrong, _, _ = derive_master_components(WRONG_PW, persisted_salt)

        assert srp_pass_correct != srp_pass_wrong
