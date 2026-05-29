import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

// ── Key size constants ──────────────────────────────────────────────────────

export const ED25519_PUB_BYTES  = 32
export const ED25519_SIG_BYTES  = 64
export const X25519_PUB_BYTES   = 32
export const MLDSA_PUB_BYTES    = ml_dsa65.lengths.publicKey
export const MLDSA_SIG_BYTES    = ml_dsa65.lengths.signature
export const MLKEM_PUB_BYTES    = ml_kem768.lengths.publicKey
export const SIGNING_PUB_BYTES  = ED25519_PUB_BYTES + MLDSA_PUB_BYTES
export const DUAL_SIG_BYTES     = ED25519_SIG_BYTES + MLDSA_SIG_BYTES

// ── SRP-6a parameters ───────────────────────────────────────────────────────
// RFC 5054 Appendix A §3: 2048-bit group, prime N is exactly 2048 bits.
// v = g^x mod N, A = g^a mod N, B = k*v + g^b mod N  (RFC 5054 §2.5.3–2.5.4)
// → verifier and ephemerals are at most 2048 bits = 512 hex chars.
//
// Salt: RFC 5054 §2.8.2 allows 1–255 bytes; 64 hex chars (32 bytes) is the
// secure-remote-password library default, not RFC-mandated.

export const SRP_SALT_HEX          = 64   // library default (32 bytes)
export const SRP_VERIFIER_HEX      = 512  // RFC 5054 Appendix A §3 — 2048-bit group
export const SRP_EPHEMERAL_HEX     = 512  // 2048-bit group: A,B = g^x mod N < 2^2048 → ≤256 bytes = 512 hex chars
export const SRP_EPHEMERAL_HEX_MIN = 256  // lower bound: real 2048-bit group values are always close to 512 chars;
                                          // 256 tolerates libraries that strip leading zeros without accepting garbage
export const SRP_SESSION_PROOF_HEX = 64   // M1/M2 = SHA-256 output = 32 bytes = 64 hex chars

// ── Challenge-response auth ─────────────────────────────────────────────────

export const CHALLENGE_NONCE_BYTES = 32
export const CHALLENGE_NONCE_HEX   = CHALLENGE_NONCE_BYTES * 2

// ── Input validation ────────────────────────────────────────────────────────

export const HEX_RE           = /^[0-9a-f]+$/i
export const UUID_RE          = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const USERNAME_REGEX   = /^[a-zA-Z0-9_]+$/
export const USERNAME_MIN     = 3
export const USERNAME_MAX     = 50
export const DEVICE_NAME_MAX  = 100
