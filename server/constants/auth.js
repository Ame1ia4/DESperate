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

// ── SRP-6a parameters (secure-remote-password library defaults) ─────────────
// SHA-256 hash output = 32 bytes → salt is 64 hex chars
// 2048-bit group → verifier is 512 hex chars

export const SRP_SALT_HEX     = 64
export const SRP_VERIFIER_HEX = 512

// ── Input validation ────────────────────────────────────────────────────────

export const USERNAME_REGEX   = /^[a-zA-Z0-9_]+$/
export const USERNAME_MIN     = 3
export const USERNAME_MAX     = 50
export const DEVICE_NAME_MAX  = 100
