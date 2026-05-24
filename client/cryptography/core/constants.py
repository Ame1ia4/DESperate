# ChaCha20-Poly1305 parameters (RFC 8439)
KEY_LEN: int = 32
NONCE_LEN: int = 12
TAG_LEN: int = 16
MIN_CT_LEN: int = NONCE_LEN + TAG_LEN

# Signal Double Ratchet limits
MAX_SKIP: int = 1_000           # max skipped message keys per session (§2.6)
MAX_HEADER_MESSAGES: int = 2**32 - 1  # key rotation safety bound (§4.1)

# HKDF domain separation label
NONCE_INFO: bytes = b"chacha20-poly1305-nonce-v1"
