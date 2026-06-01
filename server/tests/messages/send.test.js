// Tests for POST /messages send handler.
// Covers test matrix #1 (leaf-mismatch rejection) and the golden path.
// ⚠️  Requires merkletreejs — run `npm install --ignore-scripts` first.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { computeLeaf } from '../../blockchain/merkle-core.js'
import { sendMessage } from '../../handlers/messages/send.js'

const CONV_ID  = '11111111-1111-1111-1111-111111111111'
const MSG_ID   = '22222222-2222-2222-2222-222222222222'
const DEVICE_ID = '33333333-3333-3333-3333-333333333333'

// 12-byte nonce
const NONCE_HEX = '0'.repeat(24)

// Build a minimal Express app that stubs requireSrpSession
function makeApp() {
  const app = express()
  app.use(express.json())
  app.post('/messages', (req, _res, next) => {
    req.deviceId = DEVICE_ID
    req.userId   = '44444444-4444-4444-4444-444444444444'
    next()
  }, sendMessage)
  return app
}

let server, baseUrl

import { before, after } from 'node:test'

before(() => new Promise(resolve => {
  server  = makeApp().listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`
    resolve()
  })
}))

after(() => new Promise(resolve => server.close(resolve)))

beforeEach(() => {
  globalThis.__db.queryImpl          = null
  globalThis.__db.clientQueryResults = []
})

function validBody(overrides = {}) {
  const ct         = Buffer.alloc(64, 0xab)
  const clientLeaf = computeLeaf(ct)
  return {
    conversation_id: CONV_ID,
    ciphertext:      ct.toString('hex'),
    nonce:           NONCE_HEX,
    associated_data: 'deadbeef',
    client_leaf:     clientLeaf,
    ...overrides,
  }
}

async function post(body) {
  return fetch(`${baseUrl}/messages`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  })
}

describe('POST /messages — leaf-mismatch rejection (test matrix #1)', () => {
  it('returns 400 and writes no rows when client_leaf does not match keccak256(ciphertext)', async () => {
    let txStarted = false
    globalThis.__db.clientQueryResults = [
      { rows: [], onCall: () => { txStarted = true } },
    ]

    const body = validBody({ client_leaf: '0x' + 'aa'.repeat(32) })
    const res  = await post(body)

    assert.strictEqual(res.status, 400)
    const json = await res.json()
    assert.match(json.error, /client_leaf/)
    assert.ok(!txStarted, 'transaction must not be opened on mismatch')
  })

  it('returns 400 when ciphertext is not valid hex', async () => {
    const res = await post(validBody({ ciphertext: 'not-hex!' }))
    assert.strictEqual(res.status, 400)
  })

  it('returns 400 when nonce is wrong length', async () => {
    const res = await post(validBody({ nonce: 'aabb' }))
    assert.strictEqual(res.status, 400)
  })

  it('returns 400 when client_leaf is malformed', async () => {
    const res = await post(validBody({ client_leaf: 'short' }))
    assert.strictEqual(res.status, 400)
  })

  it('returns 400 when conversation_id is missing', async () => {
    const { conversation_id: _, ...body } = validBody()
    const res = await post(body)
    assert.strictEqual(res.status, 400)
  })
})

describe('POST /messages — golden path', () => {
  it('stores message and leaf, returns 201 with id and status=pending', async () => {
    globalThis.__db.clientQueryResults = [
      { rows: [{ id: MSG_ID }] }, // INSERT messages RETURNING id
      { rows: [] },               // INSERT merkle_leaves
    ]

    const res  = await post(validBody())
    assert.strictEqual(res.status, 201)
    const json = await res.json()
    assert.strictEqual(json.id, MSG_ID)
    assert.strictEqual(json.status, 'pending')
  })

  it('inserts merkle_leaves with state=pending', async () => {
    let leafInsertText
    globalThis.__db.clientQueryResults = [
      { rows: [{ id: MSG_ID }] },
      { rows: [], onCall: (text) => { leafInsertText = text } },
    ]

    await post(validBody())
    assert.ok(leafInsertText, 'leaf insert query must have been called')
    assert.match(leafInsertText, /merkle_leaves/)
    assert.match(leafInsertText, /pending/)
  })
})
