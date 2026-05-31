import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'

// ── Key size constants ──────────────────────────────────────────────────────

export const X25519_PUB_BYTES   = 32
export const ED25519_PUB_BYTES  = 32
export const ED25519_SIG_BYTES  = 64
export const MLDSA_PUB_BYTES    = ml_dsa87.lengths.publicKey   // 2592 bytes (ML-DSA-87)
export const MLDSA_SIG_BYTES    = ml_dsa87.lengths.signature   // 4627 bytes (ML-DSA-87)
export const MLKEM_PUB_BYTES    = ml_kem1024.lengths.publicKey // 1568 bytes (ML-KEM-1024)
// Hybrid signing public key: [ed25519_pub (32 B) || ml_dsa87_pub (2592 B)]
export const SIGNING_PUB_BYTES  = ED25519_PUB_BYTES + MLDSA_PUB_BYTES  // 2624 bytes
// Dual signature: [ed25519_sig (64 B) || ml_dsa87_sig (4627 B)]
export const DUAL_SIG_BYTES     = ED25519_SIG_BYTES + MLDSA_SIG_BYTES   // 4691 bytes

// ── SRP-6a parameters ───────────────────────────────────────────────────────
// RFC 5054 Appendix A §3: 2048-bit group, prime N is exactly 2048 bits.
// v = g^x mod N, A = g^a mod N, B = k*v + g^b mod N  (RFC 5054 §2.5.3–2.5.4)
// → verifier and ephemerals are at most 2048 bits = 512 hex chars.
//
// Salt: RFC 5054 §2.8.2 allows 1–255 bytes; 64 hex chars (32 bytes) is the
// secure-remote-password library default, not RFC-mandated.

export const SRP_SALT_HEX          = 64   // js-srp6a default: hashBytes['SHA-256'] = 32 bytes
export const SRP_VERIFIER_HEX      = 768  // RFC 5054 Appendix A §3 — 3072-bit group: 384 bytes = 768 hex chars
export const SRP_EPHEMERAL_HEX     = 768  // 3072-bit group: A,B = g^x mod N < 2^3072 → ≤384 bytes = 768 hex chars
export const SRP_SESSION_PROOF_HEX = 64   // M1/M2 = SHA-256 output = 32 bytes = 64 hex chars

// ── requireAuth proof ───────────────────────────────────────────────────────
// HMAC-SHA256 output = 32 bytes = 64 hex chars
export const HMAC_HEX_LEN = 64

// ── Input validation ────────────────────────────────────────────────────────

export const HEX_RE           = /^[0-9a-f]+$/i
export const UUID_RE          = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const USERNAME_REGEX   = /^[a-zA-Z0-9_]+$/
export const USERNAME_MIN     = 3
export const USERNAME_MAX     = 50
export const DEVICE_NAME_MAX  = 100
