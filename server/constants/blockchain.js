// Code-mirrored fallbacks for the system_config merkle_* keys.
// server/blockchain/config.js loads system_config at startup and
// falls back to these if a row is missing.  Keep in sync with
// the values in migration 2026060100004_merkle_system_config.sql.

// Messages per Merkle root.  Unrelated to MERKLE_MAX_ROOTS_PER_TX.
export const MERKLE_BATCH_SIZE = 100

// Cap on roots submitted in one storeBatchHashes() tx.
// Must not exceed the contract constant MAX_BATCH_SIZE (=100).
export const MERKLE_MAX_ROOTS_PER_TX       = 100

// Build a partial root when the oldest pending leaf is this old (ms).
export const MERKLE_ROOT_BUILD_INTERVAL_MS = 300_000   // 5 min

// Broadcast built roots when the oldest built root is this old (ms).
export const MERKLE_BROADCAST_INTERVAL_MS  = 1_200_000 // 20 min

// Broadcast early once this many roots are built (min batch size).
// Keeps latency low without waiting for a full 100-root batch.
export const MERKLE_BROADCAST_MIN_ROOTS    = 4

// Worker wakes at this cadence to evaluate both build + broadcast phases.
export const MERKLE_WORKER_TICK_MS         = 60_000    // 1 min

// Maximum broadcast attempts before a root transitions to state='failed'.
export const MERKLE_MAX_BROADCAST_ATTEMPTS = 5

// Postgres advisory lock key for the merkle worker (arbitrary stable int).
export const MERKLE_ADVISORY_LOCK_KEY      = 0x6d726b6c // 'mrkl' as hex
