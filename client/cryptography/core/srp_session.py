"""
core/srp_session.py

SRP-6a client session (RFC 5054, 3072-bit group, SHA-256).

Implemented from scratch to match js-srp6a (the server library) exactly:
  k  = H(N || PAD(g))        RFC 5054 §2.5.3  — g zero-padded to group width
  u  = H(PAD(A) || PAD(B))   RFC 5054 §2.5.4  — both padded to group width
  K  = H(PAD(S))             S zero-padded to group width before hashing
  M  = H(H(N)^H(g), H(I), s, A, B, K)

pysrp's default mode hashes g and S without padding, producing k/K values
that differ from js-srp6a and causing authentication to always fail.
"""

from __future__ import annotations

import hashlib
import hmac
import os

# RFC 5054 Appendix A — 3072-bit safe prime, g = 5.
_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
_N = int(_N_HEX, 16)
_g = 5
_N_BYTES = 384  # 3072 bits / 8


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _pad(n: int) -> bytes:
    """Zero-pad integer to _N_BYTES (384 bytes for the 3072-bit group)."""
    return n.to_bytes(_N_BYTES, "big")


def _minimal(n: int) -> bytes:
    """Minimal big-endian encoding (no leading zeros)."""
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big")


# k = H(N || PAD(g)) — RFC 5054 §2.5.3; computed once at import.
_k = int.from_bytes(_sha256(_pad(_N), _pad(_g)), "big")


class SrpSession:
    """
    Client-side SRP-6a session compatible with js-srp6a.

    Usage:
        session = SrpSession(username, password)
        A   = session.A_hex                       # send to server in round 1
        M1  = session.process_challenge(salt, B)  # send to server in round 2
        ok  = session.verify_server(M2)           # verify server's proof
    """

    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        a_bytes = os.urandom(32)            # 256 bits — RFC 5054 §2.5.3 minimum
        self._a = int.from_bytes(a_bytes, "big")
        self._A = pow(_g, self._a, _N)
        self._K: bytes | None = None
        self._HAMK: bytes | None = None

    @property
    def A_hex(self) -> str:
        """Client public ephemeral A as hex (minimal encoding)."""
        return _minimal(self._A).hex()

    def process_challenge(self, salt_hex: str, B_hex: str) -> str:
        """
        Process the server's round-1 response; returns M1 (client proof) as hex.

        Parameters
        ----------
        salt_hex : SRP salt from server (hex)
        B_hex    : server public ephemeral B (hex, padded to 768 chars by server)

        Raises
        ------
        ValueError : if B is invalid (B mod N == 0) or u == 0
        """
        print(
            f"[SRP CHALLENGE] process_challenge called"
            f" | salt_hex len={len(salt_hex)} value={salt_hex}"
            f" | B_hex len={len(B_hex)} first16={B_hex[:16]}",
            flush=True,
        )

        B_bytes = bytes.fromhex(B_hex)      # server sends B padded to 768 hex chars
        B = int.from_bytes(B_bytes, "big")

        if B % _N == 0:
            raise ValueError("SRP challenge rejected: B is invalid (B mod N == 0)")

        # u = H(PAD(A) || PAD(B))  — RFC 5054 §2.5.4
        u = int.from_bytes(_sha256(_pad(self._A), _pad(B)), "big")
        if u == 0:
            raise ValueError("SRP challenge rejected: u == 0")

        # x = H(salt || H(I:p))
        salt = bytes.fromhex(salt_hex)
        x = int.from_bytes(
            _sha256(salt, _sha256((self._username + ":" + self._password).encode())),
            "big",
        )

        # S = (B - k * g^x)^(a + u*x) mod N
        S = pow(B - _k * pow(_g, x, _N), self._a + u * x, _N)

        # K = H(PAD(S))
        self._K = _sha256(_pad(S))

        # M = H(H(N) XOR H(g), H(I), s, A, B, K)
        HN    = _sha256(_pad(_N))           # N is exactly 384 bytes
        Hg    = _sha256(bytes([_g]))        # g as 1 byte — matches js-srp6a H(g)
        HNxHg = bytes(a ^ b for a, b in zip(HN, Hg))
        HI    = _sha256(self._username.encode())
        A_bytes = _minimal(self._A)         # same encoding as what we sent to server
        # B_bytes kept as received: server pads B to 384 bytes (768 hex chars)
        M = _sha256(HNxHg, HI, salt, A_bytes, B_bytes, self._K)

        # HAMK = H(A, M, K) — for verifying the server's proof
        self._HAMK = _sha256(A_bytes, M, self._K)

        print(
            f"[SRP CHALLENGE] computed"
            f" | salt({len(salt)}B): {salt.hex()}"
            f" | K: {self._K.hex()}"
            f" | M1: {M.hex()}",
            flush=True,
        )

        return M.hex()

    def verify_server(self, M2_hex: str) -> bool:
        """
        Verify the server's session proof M2 (mutual authentication).

        Returns True if the server computed the same session key.
        """
        if self._HAMK is None:
            return False
        try:
            return hmac.compare_digest(self._HAMK, bytes.fromhex(M2_hex))
        except Exception:
            return False

    @property
    def session_key_hex(self) -> str:
        """SRP session key K as hex. Valid only after process_challenge() completes."""
        if self._K is None:
            raise ValueError("SRP session not completed — call process_challenge first")
        return self._K.hex()
