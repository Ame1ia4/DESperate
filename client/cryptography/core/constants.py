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

# ── PQXDH parameters (Signal PQXDH spec §3.3) ───────────────────────────────

# Padding constant prepended to IKM before HKDF — 32 bytes of 0xFF.
# Prevents cross-protocol confusion where an attacker attempts to use a
# PQXDH output as input to a different protocol. (PQXDH spec §3.3)
PQXDH_F: bytes = b"\xff" * 32

# HKDF salt for PQXDH shared-secret derivation — zero string. (PQXDH spec §3.3)
PQXDH_HKDF_SALT: bytes = b"\x00" * 32

# Output length of the PQXDH shared secret SK — 256 bits.
PQXDH_SK_LEN: int = 32

# ── ML-KEM-1024 / ML-DSA-87 algorithm identifiers (FIPS 203, FIPS 204) ──────

KEM_ALG: str = "ML-KEM-1024"
SIG_ALG: str = "ML-DSA-87"

# Expected byte sizes — asserted at startup to catch liboqs version drift.
KEM_PUBLIC_KEY_LEN: int  = 1568   # ML-KEM-1024 public key  (FIPS 203)
KEM_CIPHERTEXT_LEN: int  = 1568   # ML-KEM-1024 ciphertext  (FIPS 203)
DSA_PUBLIC_KEY_LEN: int  = 2592   # ML-DSA-87   public key  (FIPS 204)
DSA_SIGNATURE_LEN: int   = 4627   # ML-DSA-87   signature   (FIPS 204)

# Default number of one-time prekeys generated per bundle.
# Consumed one-per-session; server should alert the user when running low.
OPK_COUNT: int = 20

# ── Argon2id parameters (RFC 9106, OWASP Password Storage Cheat Sheet) ───────
#
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
# Do not reduce these values. Increasing memory_cost or time_cost improves
# security at the cost of latency.

ARGON2_TIME_COST: int    = 2        # iterations
ARGON2_MEMORY_COST: int  = 19456   # KiB = 64 MB
ARGON2_PARALLELISM: int  = 1       # threads
ARGON2_HASH_LEN: int     = 32      # bytes — 256-bit output
ARGON2_SALT_LEN: int     = 16      # bytes — 128-bit random salt per hash
