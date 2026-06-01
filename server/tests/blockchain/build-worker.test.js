// Tests for the build phase: pending leaves → built roots.
// ⚠️  Requires merkletreejs — run `npm install --ignore-scripts` first.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { computeLeaf, computeRoot } from '../../blockchain/merkle-core.js'
import { buildPendingRoots } from '../../blockchain/build-worker.js'

const CFG_DEFAULT = {
  merkle_batch_size:             100,
  merkle_root_build_interval_ms: 300_000,
}

function makeLeafRow(id, ageMs = 0) {
  const ct   = Buffer.alloc(32, id)
  const leaf = computeLeaf(ct)
  const created_at = new Date(Date.now() - ageMs).toISOString()
  return { id, leaf_hash: leaf, created_at }
}

// Helper: track calls to globalThis.__db.queryImpl / clientQueryResults
function setupDb({ countResult, leaves = [], insertedRootId = 1 }) {
  // buildPendingRoots makes these query calls in order:
  // 1. SELECT COUNT/MIN (pool.query via queryImpl)
  // 2. withTransaction → SELECT leaves FOR UPDATE SKIP LOCKED
  // 3. withTransaction → INSERT INTO merkle_roots … RETURNING id
  // 4. withTransaction → UPDATE merkle_leaves SET … (one per leaf)

  globalThis.__db.queryImpl = async (text) => {
    if (/COUNT\(\*\)/.test(text)) return { rows: [countResult] }
    throw new Error(`unexpected pool query: ${text}`)
  }

  const txResults = [
    // SELECT leaves
    { rows: leaves },
    // INSERT merkle_roots
    { rows: [{ id: insertedRootId }] },
    // UPDATE merkle_leaves (one per leaf)
    ...leaves.map(() => ({ rows: [] })),
  ]
  globalThis.__db.clientQueryResults = txResults
}

beforeEach(() => {
  globalThis.__db.queryImpl = null
  globalThis.__db.clientQueryResults = []
})

describe('buildPendingRoots()', () => {
  describe('no-op conditions', () => {
    it('does nothing when pending count is 0', async () => {
      let txStarted = false
      globalThis.__db.queryImpl = async () => ({ rows: [{ cnt: 0, oldest: null }] })
      globalThis.__db.clientQueryResults = [{ rows: [], onCall: () => { txStarted = true } }]

      await buildPendingRoots(CFG_DEFAULT)
      assert.ok(!txStarted, 'should not open a transaction when cnt=0')
    })

    it('does nothing when count < batchSize and not timed out', async () => {
      let txStarted = false
      const now = new Date().toISOString()
      globalThis.__db.queryImpl = async () => ({ rows: [{ cnt: 5, oldest: now }] })
      globalThis.__db.clientQueryResults = [{ rows: [], onCall: () => { txStarted = true } }]

      await buildPendingRoots({ ...CFG_DEFAULT, merkle_root_build_interval_ms: 999_999 })
      assert.ok(!txStarted)
    })
  })

  describe('batch-by-size (test matrix #2)', () => {
    it('builds a root when pending count >= batchSize', async () => {
      const leaves  = Array.from({ length: 100 }, (_, i) => makeLeafRow(i + 1))
      const leafHexes = leaves.map(l => l.leaf_hash)
      const expectedRoot = computeRoot(leafHexes)

      let capturedRoot
      globalThis.__db.queryImpl = async () => ({ rows: [{ cnt: 100, oldest: leaves[0].created_at }] })
      globalThis.__db.clientQueryResults = [
        { rows: leaves },
        { rows: [{ id: 1 }], onCall: (_t, params) => { capturedRoot = params[0] } },
        ...leaves.map(() => ({ rows: [] })),
      ]

      await buildPendingRoots(CFG_DEFAULT)
      assert.strictEqual(capturedRoot, expectedRoot)
    })

    it('sets limit to batchSize when full batch available', async () => {
      let capturedLimit
      const leaves = Array.from({ length: 100 }, (_, i) => makeLeafRow(i + 1))
      globalThis.__db.queryImpl = async () => ({ rows: [{ cnt: 150, oldest: new Date(0).toISOString() }] })
      globalThis.__db.clientQueryResults = [
        { rows: leaves, onCall: (_t, params) => { capturedLimit = params[0] } },
        { rows: [{ id: 1 }] },
        ...leaves.map(() => ({ rows: [] })),
      ]

      await buildPendingRoots(CFG_DEFAULT)
      assert.strictEqual(capturedLimit, 100)
    })
  })

  describe('batch-by-timeout with odd count (test matrix #3)', () => {
    it('builds a partial root from 3 leaves when oldest is timed out', async () => {
      const leaves    = [1, 2, 3].map(i => makeLeafRow(i, 400_000))
      const leafHexes = leaves.map(l => l.leaf_hash)
      const expected  = computeRoot(leafHexes)

      let capturedRoot
      globalThis.__db.queryImpl = async () => ({
        rows: [{ cnt: 3, oldest: leaves[0].created_at }],
      })
      globalThis.__db.clientQueryResults = [
        { rows: leaves },
        { rows: [{ id: 1 }], onCall: (_t, params) => { capturedRoot = params[0] } },
        { rows: [] }, { rows: [] }, { rows: [] },
      ]

      await buildPendingRoots({ ...CFG_DEFAULT, merkle_root_build_interval_ms: 300_000 })
      assert.strictEqual(capturedRoot, expected, 'root must match server-recomputed value')
    })

    it('assigns correct leaf_index values (0-based insertion order)', async () => {
      const leaves = [1, 2, 3].map(i => makeLeafRow(i, 400_000))
      const captured = []

      globalThis.__db.queryImpl = async () => ({
        rows: [{ cnt: 3, oldest: leaves[0].created_at }],
      })
      globalThis.__db.clientQueryResults = [
        { rows: leaves },
        { rows: [{ id: 7 }] },
        { rows: [], onCall: (_t, p) => captured.push({ rootId: p[0], idx: p[1], id: p[2] }) },
        { rows: [], onCall: (_t, p) => captured.push({ rootId: p[0], idx: p[1], id: p[2] }) },
        { rows: [], onCall: (_t, p) => captured.push({ rootId: p[0], idx: p[1], id: p[2] }) },
      ]

      await buildPendingRoots({ ...CFG_DEFAULT, merkle_root_build_interval_ms: 300_000 })

      for (let i = 0; i < 3; i++) {
        assert.strictEqual(captured[i].idx, i)
        assert.strictEqual(captured[i].rootId, 7)
      }
    })
  })

  describe('skips locked leaves (SKIP LOCKED)', () => {
    it('no-ops if SELECT returns 0 rows inside transaction', async () => {
      const now = new Date(Date.now() - 400_000).toISOString()
      globalThis.__db.queryImpl = async () => ({ rows: [{ cnt: 3, oldest: now }] })
      globalThis.__db.clientQueryResults = [
        { rows: [] }, // SKIP LOCKED returns nothing
      ]

      await assert.doesNotReject(() => buildPendingRoots(CFG_DEFAULT))
    })
  })
})
