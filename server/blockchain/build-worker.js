import { query, withTransaction } from '../database/db.js'
import { computeRoot } from './merkle-core.js'
import { MERKLE_ADVISORY_LOCK_KEY } from '../constants/blockchain.js'

// Build phase: turn pending merkle_leaves into built merkle_roots.
//
// Called on each worker tick.  Must be called while holding the
// Postgres advisory lock (acquired by the combined worker in publisher.js).
//
// Two triggers:
//   Full batch  — pending count ≥ batchSize → build one root of exactly
//                 batchSize leaves (oldest first).  Repeat until below.
//   Partial     — pending count < batchSize but oldest pending leaf is
//                 older than buildIntervalMs → build one root of whatever
//                 leaves are available (prevents indefinite delay for
//                 low-traffic conversations).

export async function buildPendingRoots(cfg) {
  const { merkle_batch_size: batchSize, merkle_root_build_interval_ms: buildIntervalMs } = cfg

  // Avoid the DB round-trip when there's nothing to do
  const { rows: countRows } = await query(
    `SELECT COUNT(*)::int AS cnt,
            MIN(created_at) AS oldest
     FROM merkle_leaves
     WHERE state = 'pending'`
  )

  const { cnt, oldest } = countRows[0]
  if (cnt === 0) return

  const ageMs = oldest ? Date.now() - new Date(oldest).getTime() : 0
  const hasFullBatch = cnt >= batchSize
  const hasTimedOut  = ageMs >= buildIntervalMs

  if (!hasFullBatch && !hasTimedOut) return

  // Build one root at a time inside a transaction; if a full batch exists,
  // the worker will call this function again on the next tick for the rest.
  const limit = hasFullBatch ? batchSize : cnt

  await withTransaction(async (client) => {
    // Lock the rows we're about to batch so concurrent workers (if any slip
    // through the advisory lock) cannot pick the same leaves.
    const { rows: leaves } = await client.query(
      `SELECT id, leaf_hash
       FROM merkle_leaves
       WHERE state = 'pending'
       ORDER BY created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [limit]
    )

    if (leaves.length === 0) return

    const leafHexes = leaves.map(l => l.leaf_hash.trim())
    const root      = computeRoot(leafHexes)

    // Insert the root first to get its id
    const { rows: rootRows } = await client.query(
      `INSERT INTO merkle_roots (merkle_root, state, created_at)
       VALUES ($1, 'built', now())
       RETURNING id`,
      [root]
    )
    const rootId = rootRows[0].id

    // Assign each leaf its index and link to the root
    for (let i = 0; i < leaves.length; i++) {
      await client.query(
        `UPDATE merkle_leaves
         SET merkle_root_id = $1, leaf_index = $2, state = 'batched'
         WHERE id = $3`,
        [rootId, i, leaves[i].id]
      )
    }

    console.info(`[build-worker] built root ${root} from ${leaves.length} leaves (rootId=${rootId})`)
  })
}
