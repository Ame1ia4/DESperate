import { query, withTransaction } from './db.js'
import { computeRoot } from './merkle-core.js'

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

  const { rows: countRows } = await query(
    `SELECT COUNT(*)::int AS cnt,
            MIN(created_at) AS oldest
     FROM merkle_leaves
     WHERE state = 'pending'`
  )

  const { cnt, oldest } = countRows[0]
  console.info(`[build-worker] tick: ${cnt} pending leaf(ves)`)
  if (cnt === 0) return

  const ageMs = oldest ? Date.now() - new Date(oldest).getTime() : 0
  const hasFullBatch = cnt >= batchSize
  const hasTimedOut  = ageMs >= buildIntervalMs

  console.info(`[build-worker] trigger check: fullBatch=${hasFullBatch} (${cnt}/${batchSize}), timedOut=${hasTimedOut} (age=${Math.round(ageMs / 1000)}s / ${buildIntervalMs / 1000}s)`)

  if (!hasFullBatch && !hasTimedOut) {
    console.info('[build-worker] no trigger met — skipping build')
    return
  }

  const limit = hasFullBatch ? batchSize : cnt
  console.info(`[build-worker] building root from up to ${limit} leaf(ves)`)

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

    if (leaves.length === 0) {
      console.info('[build-worker] no leaves locked (all taken by concurrent worker) — skipping')
      return
    }

    console.info(`[build-worker] locked ${leaves.length} leaf(ves): ids=[${leaves.map(l => l.id).join(', ')}]`)

    const leafHexes = leaves.map(l => l.leaf_hash.trim())
    const root      = computeRoot(leafHexes)
    console.info(`[build-worker] computed root: ${root}`)

    const { rows: rootRows } = await client.query(
      `INSERT INTO merkle_roots (merkle_root, state, created_at)
       VALUES ($1, 'built', now())
       RETURNING id`,
      [root]
    )
    const rootId = rootRows[0].id
    console.info(`[build-worker] inserted merkle_roots row id=${rootId}`)

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

    console.info(`[build-worker] built root ${root} from ${leaves.length} leaf(ves) (rootId=${rootId}) ✓`)
  })
}
