// Code-mirrored fallbacks for the system_config merkle_* keys.
// config.js loads system_config at startup and falls back to these if a row is missing.
// Keep in sync with migration 2026060100004_merkle_system_config.sql.

export const MERKLE_BATCH_SIZE = 100

// Must not exceed the contract constant MAX_BATCH_SIZE (=100).
export const MERKLE_MAX_ROOTS_PER_TX       = 100

export const MERKLE_ROOT_BUILD_INTERVAL_MS = 300_000   // 5 min
export const MERKLE_BROADCAST_INTERVAL_MS  = 1_200_000 // 20 min
export const MERKLE_BROADCAST_MIN_ROOTS    = 4
export const MERKLE_WORKER_TICK_MS         = 60_000    // 1 min
export const MERKLE_MAX_BROADCAST_ATTEMPTS = 5

export const MERKLE_ADVISORY_LOCK_KEY      = 0x6d726b6c // 'mrkl' as hex
