import { query } from '../database/db.js'
import {
  MERKLE_BATCH_SIZE,
  MERKLE_MAX_ROOTS_PER_TX,
  MERKLE_ROOT_BUILD_INTERVAL_MS,
  MERKLE_BROADCAST_INTERVAL_MS,
  MERKLE_BROADCAST_MIN_ROOTS,
  MERKLE_WORKER_TICK_MS,
  MERKLE_MAX_BROADCAST_ATTEMPTS,
} from '../constants/blockchain.js'

const KEYS = [
  'merkle_batch_size',
  'merkle_root_build_interval_ms',
  'merkle_broadcast_interval_ms',
  'merkle_broadcast_min_roots',
  'merkle_max_roots_per_tx',
  'merkle_worker_tick_ms',
  'merkle_max_broadcast_attempts',
]

const FALLBACKS = {
  merkle_batch_size:             MERKLE_BATCH_SIZE,
  merkle_root_build_interval_ms: MERKLE_ROOT_BUILD_INTERVAL_MS,
  merkle_broadcast_interval_ms:  MERKLE_BROADCAST_INTERVAL_MS,
  merkle_broadcast_min_roots:    MERKLE_BROADCAST_MIN_ROOTS,
  merkle_max_roots_per_tx:       MERKLE_MAX_ROOTS_PER_TX,
  merkle_worker_tick_ms:         MERKLE_WORKER_TICK_MS,
  merkle_max_broadcast_attempts: MERKLE_MAX_BROADCAST_ATTEMPTS,
}

export async function loadMerkleConfig() {
  const { rows } = await query(
    `SELECT key, value FROM system_config WHERE key = ANY($1::text[])`,
    [KEYS]
  )

  const cfg = { ...FALLBACKS }
  for (const { key, value } of rows) {
    const parsed = parseInt(value, 10)
    if (!Number.isInteger(parsed)) {
      console.warn(`[merkle-config] invalid value for ${key}: ${value} — using fallback`)
      continue
    }
    cfg[key] = parsed
  }

  console.info('[merkle-config] loaded', cfg)
  return cfg
}
