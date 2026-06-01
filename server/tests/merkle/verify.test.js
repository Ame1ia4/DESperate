// Tests for GET /messages/:id/verify (test matrix #7, #9, #11).
// Covers: deletion gates (global + per-user), status mapping, membership gate.
// ⚠️  Requires merkletreejs — run `npm install --ignore-scripts` first.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { computeLeaf, computeRoot } from '../../blockchain/merkle-core.js'
import { verifyHandler } from '../../handlers/merkle/verify.js'

const MSG_ID    = '11111111-1111-1111-1111-111111111111'
const USER_ID   = '22222222-2222-2222-2222-222222222222'
const DEVICE_ID = '33333333-3333-3333-3333-333333333333'

function makeApp() {
  const app = express()
  app.use(express.json())
  app.get('/messages/:id/blockchain-verify', (req, _res, next) => {
    req.deviceId = DEVICE_ID
    req.userId   = USER_ID
    next()
  }, verifyHandler)
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

beforeEach(() => {
  globalThis.__db.queryImpl = null
})

function getVerify(msgId = MSG_ID) {
  return fetch(`${baseUrl}/messages/${msgId}/blockchain-verify`)
}

// Build a confirmed-root fixture for end-to-end tests
function buildFixture(leafCount = 3, targetIndex = 1) {
  const cts    = Array.from({ length: leafCount }, (_, i) => Buffer.alloc(32, i + 1))
  const leaves = cts.map(computeLeaf)
  const root   = computeRoot(leaves)
  return { cts, leaves, root, targetIndex }
}

// queryImpl call order for verifyHandler:
// 1. member check
// 2. message + deleted_at
// 3. message_hidden check
// 4. merkle_leaves + root join
function setupQueries(calls) {
  let i = 0
  globalThis.__db.queryImpl = async (text) => {
    const result = calls[i++]
    if (!result) throw new Error(`Unexpected query #${i}: ${text.slice(0, 60)}`)
    if (result instanceof Error) throw result
    return result
  }
}

describe('GET /messages/:id/verify', () => {
  describe('membership gate (test matrix #11)', () => {
    it('returns 403 when requester is not a conversation member', async () => {
      setupQueries([{ rows: [] }]) // membership check returns no row
      const res = await getVerify()
      assert.strictEqual(res.status, 403)
    })
  })

  describe('deletion gates — nothing status (test matrix #7)', () => {
    it('returns status=nothing when messages.deleted_at is set (delete-for-everyone)', async () => {
      setupQueries([
        { rows: [{ id: MSG_ID }] }, // member check
        { rows: [{ id: MSG_ID, deleted_at: new Date().toISOString(), conversation_id: 'x', ciphertext_hex: 'aa' }] },
      ])
      const res  = await getVerify()
      assert.strictEqual(res.status, 200)
      const json = await res.json()
      assert.strictEqual(json.status, 'nothing')
    })

    it('returns status=nothing when a message_hidden row exists for the user (delete-for-self)', async () => {
      setupQueries([
        { rows: [{ id: MSG_ID }] },
        { rows: [{ id: MSG_ID, deleted_at: null, conversation_id: 'x', ciphertext_hex: 'aa' }] },
        { rows: [{ 1: 1 }] }, // hidden row found
      ])
      const res  = await getVerify()
      const json = await res.json()
      assert.strictEqual(json.status, 'nothing')
    })

    it('returns status=nothing when message does not exist', async () => {
      setupQueries([
        { rows: [{ id: MSG_ID }] },
        { rows: [] }, // message not found
      ])
      const res  = await getVerify()
      const json = await res.json()
      assert.strictEqual(json.status, 'nothing')
    })
  })

  describe('pending status', () => {
    it('returns status=pending when no leaf exists', async () => {
      setupQueries([
        { rows: [{ id: MSG_ID }] },
        { rows: [{ id: MSG_ID, deleted_at: null, conversation_id: 'x', ciphertext_hex: 'aa' }] },
        { rows: [] }, // not hidden
        { rows: [] }, // no leaf
      ])
      const res  = await getVerify()
      const json = await res.json()
      assert.strictEqual(json.status, 'pending')
    })

    it('returns status=pending when root is built but not confirmed', async () => {
      setupQueries([
        { rows: [{ id: MSG_ID }] },
        { rows: [{ id: MSG_ID, deleted_at: null, conversation_id: 'x', ciphertext_hex: 'aa' }] },
        { rows: [] },
        { rows: [{ leaf_hash: '0x' + 'aa'.repeat(32), leaf_index: 0, root_id: 1, merkle_root: '0x' + 'bb'.repeat(32), tx_hash: null, block_timestamp: null, root_state: 'built', leaf_state: 'batched' }] },
      ])
      const res  = await getVerify()
      const json = await res.json()
      assert.strictEqual(json.status, 'pending')
    })
  })

  describe('stored-on-blockchain status (test matrix #9)', () => {
    it('returns status=stored-on-blockchain when root is confirmed', async () => {
      const fx = buildFixture(3, 1)

      setupQueries([
        { rows: [{ id: MSG_ID }] },
        { rows: [{ id: MSG_ID, deleted_at: null, conversation_id: 'x', ciphertext_hex: fx.cts[1].toString('hex') }] },
        { rows: [] },
        { rows: [{ leaf_hash: fx.leaves[1], leaf_index: 1, root_id: 7, merkle_root: fx.root, tx_hash: '0x' + 'cc'.repeat(32), block_timestamp: 1700000000, root_state: 'confirmed', leaf_state: 'confirmed' }] },
      ])

      const res  = await getVerify()
      assert.strictEqual(res.status, 200)
      const json = await res.json()
      assert.strictEqual(json.status, 'stored-on-blockchain')
      assert.ok(json.tx_hash)
      assert.ok(json.block_timestamp)
      assert.ok(json.ciphertext)
      assert.ok(json.merkle_root)
      assert.strictEqual(json.proof, undefined)
    })
  })

  describe('invalid message id', () => {
    it('returns 400 for non-UUID id', async () => {
      const res = await fetch(`${baseUrl}/messages/not-a-uuid/blockchain-verify`)
      assert.strictEqual(res.status, 400)
    })
  })
})
