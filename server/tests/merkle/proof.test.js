// Tests for POST /blockchain/verify-leaf
// ⚠️  Requires merkletreejs — run `npm install --ignore-scripts` first.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { computeLeaf, computeRoot } from '../../blockchain/merkle-core.js'
import { proofHandler } from '../../handlers/merkle/proof.js'

function makeApp() {
  const app = express()
  app.use(express.json())
  app.post('/blockchain/verify-leaf', proofHandler)
  return app
}

let server, baseUrl

import { before, after } from 'node:test'

before(() => new Promise(resolve => {
  server = makeApp().listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`
    resolve()
  })
}))

after(() => new Promise(resolve => server.close(resolve)))

beforeEach(() => { globalThis.__db.queryImpl = null })

function post(body) {
  return fetch(`${baseUrl}/blockchain/verify-leaf`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  })
}

function buildFixture(count = 4, targetIndex = 2) {
  const cts    = Array.from({ length: count }, (_, i) => Buffer.alloc(32, i + 1))
  const leaves = cts.map(computeLeaf)
  const root   = computeRoot(leaves)
  return { cts, leaves, root, targetIndex }
}

function setupQueries(calls) {
  let i = 0
  globalThis.__db.queryImpl = async (text) => {
    const r = calls[i++]
    if (!r) throw new Error(`Unexpected query #${i}: ${text.slice(0, 60)}`)
    return r
  }
}

describe('POST /blockchain/verify-leaf', () => {
  describe('input validation', () => {
    it('returns 400 when leaf is missing', async () => {
      const res = await post({ root: '0x' + 'aa'.repeat(32) })
      assert.strictEqual(res.status, 400)
    })

    it('returns 400 when root is missing', async () => {
      const res = await post({ leaf: '0x' + 'aa'.repeat(32) })
      assert.strictEqual(res.status, 400)
    })

    it('returns 400 when leaf is not 64 hex chars', async () => {
      const res = await post({ leaf: '0xshort', root: '0x' + 'aa'.repeat(32) })
      assert.strictEqual(res.status, 400)
    })
  })

  describe('not found cases', () => {
    it('returns verified=false when root is not confirmed', async () => {
      setupQueries([{ rows: [] }]) // root lookup returns nothing
      const res  = await post({ leaf: '0x' + 'aa'.repeat(32), root: '0x' + 'bb'.repeat(32) })
      const body = await res.json()
      assert.strictEqual(body.verified, false)
    })

    it('returns verified=false when leaf is not in the root', async () => {
      const fx = buildFixture(4, 0)
      const wrongLeaf = computeLeaf(Buffer.alloc(32, 0xff))

      setupQueries([
        { rows: [{ id: 1 }] },                              // root found
        { rows: fx.leaves.map(l => ({ leaf_hash: l })) },  // leaves for root
      ])

      const res  = await post({ leaf: wrongLeaf, root: fx.root })
      const body = await res.json()
      assert.strictEqual(body.verified, false)
    })
  })

  describe('verified=true (test matrix #9)', () => {
    it('returns verified=true when leaf is genuinely in the root', async () => {
      const fx = buildFixture(4, 2)

      setupQueries([
        { rows: [{ id: 5 }] },
        { rows: fx.leaves.map(l => ({ leaf_hash: l })) },
      ])

      const res  = await post({ leaf: fx.leaves[fx.targetIndex], root: fx.root })
      assert.strictEqual(res.status, 200)
      const body = await res.json()
      assert.strictEqual(body.verified, true)
    })

    it('works for all leaf positions in the tree', async () => {
      const fx = buildFixture(4)

      for (let i = 0; i < fx.leaves.length; i++) {
        setupQueries([
          { rows: [{ id: 1 }] },
          { rows: fx.leaves.map(l => ({ leaf_hash: l })) },
        ])

        const res  = await post({ leaf: fx.leaves[i], root: fx.root })
        const body = await res.json()
        assert.strictEqual(body.verified, true, `leaf index ${i} should verify`)
      }
    })

    it('returns verified=false for a tampered leaf (test matrix #9)', async () => {
      const fx         = buildFixture(4, 0)
      const tamperedLeaf = computeLeaf(Buffer.alloc(32, 0xde))

      setupQueries([
        { rows: [{ id: 1 }] },
        { rows: fx.leaves.map(l => ({ leaf_hash: l })) },
      ])

      const res  = await post({ leaf: tamperedLeaf, root: fx.root })
      const body = await res.json()
      assert.strictEqual(body.verified, false)
    })
  })
})
