"""
testing/test_srp.py

Tests for core/srp_session.py — SRP-6a client session.

Run with: pytest testing/test_srp.py -v
"""

import pytest
import srp

from core.srp_session import SrpSession, _SRP_3072_KWARGS


USERNAME = "testuser"
PASSWORD = "correct-horse-battery-staple"
WRONG_PW = "wrong-password"


# ── A value (client public ephemeral) ─────────────────────────────────────────

class TestAValue:

    def test_A_hex_is_at_least_64_chars(self):
        """RFC 5054 §2.5.3: a SHOULD be ≥256 bits → A_hex ≥ 64 hex chars."""
        session = SrpSession(USERNAME, PASSWORD)
        assert len(session.A_hex) >= 64

    def test_A_hex_is_valid_hex(self):
        session = SrpSession(USERNAME, PASSWORD)
        bytes.fromhex(session.A_hex)  # raises if not valid hex

    def test_two_sessions_produce_different_A(self):
        """Each session generates a fresh random a — A must differ."""
        s1 = SrpSession(USERNAME, PASSWORD)
        s2 = SrpSession(USERNAME, PASSWORD)
        assert s1.A_hex != s2.A_hex


# ── process_challenge (M1 derivation) ─────────────────────────────────────────

class TestProcessChallenge:

    def test_process_challenge_returns_64_char_hex(self):
        """M1 = SHA-256 output = 32 bytes = 64 hex chars."""
        salt, vkey = srp.create_salted_verification_key(
            USERNAME, PASSWORD, **_SRP_3072_KWARGS
        )
        session = SrpSession(USERNAME, PASSWORD)
        A_bytes = bytes.fromhex(session.A_hex)

        svr = srp.Verifier(USERNAME, salt, vkey, A_bytes,
                           **_SRP_3072_KWARGS)
        _s, B = svr.get_challenge()

        M1_hex = session.process_challenge(salt.hex(), B.hex())
        assert len(M1_hex) == 64
        bytes.fromhex(M1_hex)  # valid hex

    def test_process_challenge_rejects_zero_B(self):
        """B mod N == 0 is an invalid ephemeral — must raise ValueError."""
        salt, _vkey = srp.create_salted_verification_key(
            USERNAME, PASSWORD, **_SRP_3072_KWARGS
        )
        session = SrpSession(USERNAME, PASSWORD)
        with pytest.raises(ValueError, match="invalid"):
            session.process_challenge(salt.hex(), "00" * 256)


# ── Full loopback (verify_server) ─────────────────────────────────────────────

class TestVerifyServer:

    def _loopback(self, client_password: str, server_password: str):
        """
        Run a full SRP exchange between SrpSession (client) and pysrp Verifier (server).
        Returns (client_authenticated, server_authenticated).
        """
        salt, vkey = srp.create_salted_verification_key(
            USERNAME, server_password, **_SRP_3072_KWARGS
        )

        client = SrpSession(USERNAME, client_password)
        A_bytes = bytes.fromhex(client.A_hex)

        svr = srp.Verifier(USERNAME, salt, vkey, A_bytes,
                           **_SRP_3072_KWARGS)
        _s, B = svr.get_challenge()

        M1_hex = client.process_challenge(salt.hex(), B.hex())
        M2     = svr.verify_session(bytes.fromhex(M1_hex))

        server_auth = svr.authenticated()
        if M2 is None:
            return False, server_auth

        client_auth = client.verify_server(M2.hex())
        return client_auth, server_auth

    def test_correct_password_authenticates_both_sides(self):
        client_ok, server_ok = self._loopback(PASSWORD, PASSWORD)
        assert client_ok is True
        assert server_ok is True

    def test_wrong_client_password_fails(self):
        """Wrong password: server rejects M1, no M2 returned → client not authenticated."""
        client_ok, server_ok = self._loopback(WRONG_PW, PASSWORD)
        assert client_ok is False
        assert server_ok is False

    def test_tampered_M2_rejected_by_client(self):
        """Client must reject a forged server proof."""
        salt, vkey = srp.create_salted_verification_key(
            USERNAME, PASSWORD, **_SRP_3072_KWARGS
        )
        client = SrpSession(USERNAME, PASSWORD)
        A_bytes = bytes.fromhex(client.A_hex)

        svr = srp.Verifier(USERNAME, salt, vkey, A_bytes,
                           **_SRP_3072_KWARGS)
        _s, B = svr.get_challenge()

        M1_hex = client.process_challenge(salt.hex(), B.hex())
        svr.verify_session(bytes.fromhex(M1_hex))

        fake_M2 = "ab" * 32  # 64 hex chars, random garbage
        assert client.verify_server(fake_M2) is False
