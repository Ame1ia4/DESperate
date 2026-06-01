"""
testing/test_srp.py

Tests for core/srp_session.py — SRP-6a client session.

The server-side is emulated by _SrpServer, which uses the same formulas as
js-srp6a (the real server library).  Tests against pysrp.Verifier would use
different k/u/K computations and do not validate actual interoperability.

Run with: pytest testing/test_srp.py -v
"""

import hmac
import os

import pytest
import srp

from core.srp_session import (
    SrpSession,
    _N, _g, _k, _sha256, _pad, _minimal, _N_HEX, _N_BYTES,
)

USERNAME = "testuser"
PASSWORD = "correct-horse-battery-staple"
WRONG_PW = "wrong-password"

# pysrp kwargs — used only to generate a verifier for the server emulator.
_SRP_3072_KWARGS: dict = {
    "hash_alg": srp.SHA256,
    "ng_type":  srp.NG_CUSTOM,
    "n_hex":    _N_HEX.encode("ascii"),
    "g_hex":    b"5",
}


class _SrpServer:
    """
    Minimal SRP-6a server emulator matching js-srp6a's exact math.

    Uses the same k, u, K, M formulas as the real Node.js server so that
    loopback tests actually validate interoperability.
    """

    def __init__(self, username: str, salt_hex: str, verifier_hex: str) -> None:
        v = int.from_bytes(bytes.fromhex(verifier_hex), "big")
        b = int.from_bytes(os.urandom(32), "big")
        B = (_k * v + pow(_g, b, _N)) % _N

        self._username = username
        self._salt     = bytes.fromhex(salt_hex)
        self._v        = v
        self._b        = b
        self._B        = B
        self._B_bytes  = B.to_bytes(_N_BYTES, "big")   # padded to 384 bytes

    @property
    def B_hex(self) -> str:
        return self._B_bytes.hex()

    def verify_session(self, A_hex: str, M1_hex: str):
        """
        Verify M1 and return (M2_hex, authenticated).
        Returns (None, False) if M1 is invalid.
        """
        A_bytes = bytes.fromhex(A_hex)
        A       = int.from_bytes(A_bytes, "big")
        M1      = bytes.fromhex(M1_hex)

        if A % _N == 0:
            return None, False

        u = int.from_bytes(_sha256(_pad(A), _pad(self._B)), "big")
        S = pow(A * pow(self._v, u, _N), self._b, _N)
        K = _sha256(_pad(S))

        HN    = _sha256(_pad(_N))
        Hg    = _sha256(bytes([_g]))
        HNxHg = bytes(a ^ b for a, b in zip(HN, Hg))
        HI    = _sha256(self._username.encode())

        M = _sha256(HNxHg, HI, self._salt, A_bytes, self._B_bytes, K)

        if not hmac.compare_digest(M, M1):
            return None, False

        P = _sha256(A_bytes, M, K)
        return P.hex(), True


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
        svr = _SrpServer(USERNAME, salt.hex(), vkey.hex())

        M1_hex = session.process_challenge(salt.hex(), svr.B_hex)
        assert len(M1_hex) == 64
        bytes.fromhex(M1_hex)  # valid hex

    def test_process_challenge_rejects_zero_B(self):
        """B mod N == 0 is an invalid ephemeral — must raise ValueError."""
        salt, _vkey = srp.create_salted_verification_key(
            USERNAME, PASSWORD, **_SRP_3072_KWARGS
        )
        session = SrpSession(USERNAME, PASSWORD)
        with pytest.raises(ValueError, match="invalid"):
            session.process_challenge(salt.hex(), "00" * 384)


# ── Full loopback (verify_server) ─────────────────────────────────────────────

class TestVerifyServer:

    def _loopback(self, client_password: str, server_password: str):
        """
        Run a full SRP exchange between SrpSession (client) and _SrpServer.
        Returns (client_authenticated, server_authenticated).
        """
        salt, vkey = srp.create_salted_verification_key(
            USERNAME, server_password, **_SRP_3072_KWARGS
        )

        client = SrpSession(USERNAME, client_password)
        svr    = _SrpServer(USERNAME, salt.hex(), vkey.hex())

        M1_hex             = client.process_challenge(salt.hex(), svr.B_hex)
        M2_hex, server_ok  = svr.verify_session(client.A_hex, M1_hex)

        if M2_hex is None:
            return False, server_ok

        client_ok = client.verify_server(M2_hex)
        return client_ok, server_ok

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
        svr    = _SrpServer(USERNAME, salt.hex(), vkey.hex())

        M1_hex = client.process_challenge(salt.hex(), svr.B_hex)
        svr.verify_session(client.A_hex, M1_hex)

        fake_M2 = "ab" * 32  # 64 hex chars, random garbage
        assert client.verify_server(fake_M2) is False
