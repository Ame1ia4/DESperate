"""
core/srp_session.py

SRP-6a client session (RFC 5054, 3072-bit group, SHA-256).

Wraps pysrp's srp.User for the two-round authentication exchange.
State is held in memory between rounds — the session object must be kept
alive from srp_start through srp_verify.

Compatibility:
  Parameters match the server's secure-remote-password npm library:
    hash_alg  : SHA-256
    ng_type   : NG_3072 (RFC 5054 Appendix A, 3072-bit safe prime, g=2)
    k         : H(N, g)     — SRP-6a multiplier
    x         : H(s|H(I:P)) — RFC 5054 §2.3

References:
  RFC 5054  SRP for TLS: https://www.rfc-editor.org/rfc/rfc5054
  pysrp:                 https://github.com/cocagne/pysrp
"""

from __future__ import annotations

import srp

# RFC 5054 Appendix A — 3072-bit safe prime, g = 2.
# pysrp 1.0.21 has no NG_3072 constant, so we pass the group explicitly via
# NG_CUSTOM. One definition here; everything else imports _SRP_3072_KWARGS.
_N_3072_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
_SRP_3072_KWARGS: dict = {
    "hash_alg": srp.SHA256,
    "ng_type":  srp.NG_CUSTOM,
    # _ctsrp (OpenSSL/ctypes backend used on Linux) types n_hex/g_hex as
    # c_char_p and raises ArgumentError when given a str.  Encode to bytes so
    # both the C extension and the pure-Python fallback accept the values.
    "n_hex":    _N_3072_HEX.encode("ascii"),
    "g_hex":    b"5",  # RFC 5054 Appendix A: 3072-bit group uses g=5, not g=2
}


class SrpSession:
    """
    Client-side SRP-6a session.

    Usage:
        session = SrpSession(username, password)
        A   = session.A_hex                       # send to server in round 1
        M1  = session.process_challenge(salt, B)  # send to server in round 2
        ok  = session.verify_server(M2)           # verify server's proof
    """

    def __init__(self, username: str, password: str) -> None:
        self._user = srp.User(username, password, **_SRP_3072_KWARGS)
        _uname, self._A_bytes = self._user.start_authentication()

    @property
    def A_hex(self) -> str:
        """
        Client public ephemeral A as a hex string.

        RFC 5054 §2.5.3: a (and therefore A) SHOULD be at least 256 bits.
        Raises ValueError if the library produced a short value.
        """
        a_hex = self._A_bytes.hex()
        if len(a_hex) < 64:
            raise ValueError(
                f"SRP a too short: need ≥256 bits, got {len(a_hex) * 4} bits"
            )
        return a_hex

    def process_challenge(self, salt_hex: str, B_hex: str) -> str:
        """
        Process the server's round-1 response and return M1 (client proof) as hex.

        Parameters
        ----------
        salt_hex : server-returned SRP salt (hex)
        B_hex    : server public ephemeral B (hex)

        Raises
        ------
        ValueError : if B is invalid (B mod N == 0) — pysrp returns None for M1
        """
        salt = bytes.fromhex(salt_hex)
        B    = bytes.fromhex(B_hex)
        M1   = self._user.process_challenge(salt, B)
        if M1 is None:
            raise ValueError("SRP challenge rejected: B is invalid (B mod N == 0)")
        return M1.hex()

    def verify_server(self, M2_hex: str) -> bool:
        """
        Verify the server's session proof M2 (mutual authentication).

        Returns True if the server knows the same session key — the password
        matched and the server is authentic. Returns False on mismatch.
        """
        try:
            self._user.verify_session(bytes.fromhex(M2_hex))
        except Exception:
            return False
        return self._user.authenticated()

    @property
    def session_key_hex(self) -> str:
        """
        The SRP session key K as a hex string.

        Both client and server independently derive the same K from the SRP
        exchange (RFC 5054 §2.6). The client uses K as the Bearer token for
        subsequent API calls; the server stores the same value via storeSessionKey.

        Only valid after a successful verify_server() call.
        """
        return self._user.session_key.hex()
