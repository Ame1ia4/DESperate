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

# Ed25519 (FIPS 186-5, RFC 8032) key and signature sizes
ED25519_PUBLIC_KEY_LEN: int = 32   # Ed25519 public key
ED25519_SIGNATURE_LEN: int  = 64   # Ed25519 signature

# Hybrid (Ed25519 ‖ ML-DSA-87) concatenated sizes — must match server/constants/auth.js
HYBRID_PUBLIC_KEY_LEN: int  = ED25519_PUBLIC_KEY_LEN + DSA_PUBLIC_KEY_LEN   # 2624
HYBRID_SIGNATURE_LEN: int   = ED25519_SIGNATURE_LEN  + DSA_SIGNATURE_LEN    # 4691

# Default number of one-time prekeys generated per bundle.
# Consumed one-per-session; server should alert the user when running low.
OPK_COUNT: int = 20

# ── Argon2id parameters (RFC 9106, OWASP Password Storage Cheat Sheet) ───────
#
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
# Do not reduce these values. Increasing memory_cost or time_cost improves
# security at the cost of latency.
#
# L2 fix: previous values (time=1, mem=47104 KiB, p=1) were below the OWASP
# minimum for Argon2id (time≥2, mem≥64 MiB, p≥1). Updated to the OWASP-preferred
# configuration: time=3, mem=65536 KiB (64 MiB), p=4. The password.py module
# docstring previously described these correct values but the constants
# themselves were lower — now they match.
#
# L3 note: these parameters govern BOTH argon2id_derive_key (local keystore,
# actively used) and argon2id_hash/argon2id_verify (server-side password
# hashing, currently dead code — the server authenticates via SRP, not Argon2).

ARGON2_TIME_COST: int    = 3        # iterations  (OWASP preferred minimum)
ARGON2_MEMORY_COST: int  = 65536   # KiB = 64 MiB (OWASP preferred minimum)
ARGON2_PARALLELISM: int  = 4       # threads      (OWASP preferred minimum)
ARGON2_HASH_LEN: int     = 32      # bytes — 256-bit output
ARGON2_SALT_LEN: int     = 16      # bytes — 128-bit random salt per hash
