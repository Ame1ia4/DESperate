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
        self._user = srp.User(
            username,
            password,
            hash_alg=srp.SHA256,
            ng_type=srp.NG_3072,
        )
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
