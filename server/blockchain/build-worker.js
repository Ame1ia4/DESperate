import { query, withTransaction } from './db.js'
import { computeRoot } from './merkle-core.js'

// Two triggers:
//   Full batch — pending count >= batchSize → build one root of exactly batchSize leaves (oldest first).
//   Partial    — oldest pending leaf older than buildIntervalMs → build from whatever is available.

export async function buildPendingRoots(cfg) {
  const { merkle_batch_size: batchSize, merkle_root_build_interval_ms: buildIntervalMs } = cfg

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

  const limit = hasFullBatch ? batchSize : cnt

  await withTransaction(async (client) => {
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

    const { rows: rootRows } = await client.query(
      `INSERT INTO merkle_roots (merkle_root, state, created_at)
       VALUES ($1, 'built', now())
       RETURNING id`,
      [root]
    )
    const rootId = rootRows[0].id

    const ids     = leaves.map(l => l.id)
    const indexes = leaves.map((_, i) => i)
    await client.query(
      `UPDATE merkle_leaves
       SET merkle_root_id = $1,
           leaf_index     = t.idx,
           state          = 'batched'
       FROM (SELECT unnest($2::int[]) AS id, unnest($3::int[]) AS idx) AS t
       WHERE merkle_leaves.id = t.id`,
      [rootId, ids, indexes]
    )
  })
}
