import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

// ── Key size constants ──────────────────────────────────────────────────────

export const ED25519_PUB_BYTES  = 32
export const ED25519_SIG_BYTES  = 64
export const X25519_PUB_BYTES   = 32
export const MLDSA_PUB_BYTES    = ml_dsa65.publicKeyLen
export const MLDSA_SIG_BYTES    = ml_dsa65.signatureLen
export const MLKEM_PUB_BYTES    = ml_kem768.publicKeyLen
export const SIGNING_PUB_BYTES  = ED25519_PUB_BYTES + MLDSA_PUB_BYTES
export const DUAL_SIG_BYTES     = ED25519_SIG_BYTES + MLDSA_SIG_BYTES

// ── Argon2id parameters (OWASP 2025 minimum) ───────────────────────────────

export const ARGON2_MEMORY_COST = 19456  // 19MB
export const ARGON2_TIME_COST   = 2
export const ARGON2_PARALLELISM = 1

// ── Input validation ────────────────────────────────────────────────────────

export const USERNAME_REGEX   = /^[a-zA-Z0-9_]+$/
export const USERNAME_MIN     = 3
export const USERNAME_MAX     = 50
export const PASSWORD_MIN     = 12
export const DEVICE_NAME_MAX  = 100
export const FINGERPRINT_MAX  = 128   // matches VARCHAR(128) in schema
export const OPK_MAX          = 100
