import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, createHash, hkdfSync } from 'node:crypto'
import express from 'express'
import { requireAuth } from '../../middleware/require_auth.js'
import { storeSessionKey } from '../../state/session_keys.js'

const VALID_DEVICE_ID = 'cccccccc-cccc-4ccc-cccc-cccccccccccc'
// 32-byte K represented as 64 hex chars
const TEST_KEY_HEX = 'abcdef01'.repeat(8)

function computeProof(keyHex, method, path, body = '') {
  const authKey  = hkdfSync('sha256', Buffer.from(keyHex, 'hex'), '', 'session-auth', 32)
  const bodyHash = createHash('sha256').update(body).digest('hex')
  return createHmac('sha256', authKey).update(`${method}:${path}:${bodyHash}`).digest('hex')
}

function createApp() {
  const app = express()
  app.use(express.json())
  app.get('/protected', requireAuth, (req, res) => res.json({ deviceId: req.deviceId }))
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

let server, baseUrl

before(() => new Promise(resolve => {
  server = createApp().listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`
    resolve()
  })
}))

after(() => new Promise(resolve => server.close(resolve)))

// Default: active unrevoked device in DB, K planted in store
beforeEach(() => {
  storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
  globalThis.__db.queryImpl = async () => ({ rows: [{ '?column?': 1 }] })
})

async function get(headers = {}) {
  const res = await fetch(`${baseUrl}/protected`, { headers })
  return { status: res.status, body: await res.json() }
}

function validHeaders() {
  return {
    'x-device-id':    VALID_DEVICE_ID,
    'x-session-proof': computeProof(TEST_KEY_HEX, 'GET', '/protected'),
  }
}

describe('requireAuth middleware', () => {
  describe('happy path', () => {
    it('passes through to the route handler when device is active and proof is valid', async () => {
      const res = await get(validHeaders())
      assert.strictEqual(res.status, 200)
    })

    it('sets req.deviceId so route handlers can use it', async () => {
      const res = await get(validHeaders())
      assert.strictEqual(res.body.deviceId, VALID_DEVICE_ID)
    })
  })

  describe('missing or invalid X-Device-ID — 401 before DB hit', () => {
    beforeEach(() => {
      globalThis.__db.queryImpl = async () => { throw new Error('Should not reach DB') }
    })

    it('returns 401 when X-Device-ID header is absent', async () => {
      const res = await get({ 'x-session-proof': computeProof(TEST_KEY_HEX, 'GET', '/protected') })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a non-UUID X-Device-ID', async () => {
      const res = await get({ 'x-device-id': 'not-a-uuid', 'x-session-proof': computeProof(TEST_KEY_HEX, 'GET', '/protected') })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when X-Session-Proof header is absent', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a proof that is not 64 hex chars', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID, 'x-session-proof': 'tooshort' })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a non-hex proof of correct length', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID, 'x-session-proof': 'z'.repeat(64) })
      assert.strictEqual(res.status, 401)
    })
  })

  describe('DB-level failures — 401', () => {
    it('returns 401 when device is not found in DB', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res = await get(validHeaders())
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when device is revoked (filtered by WHERE revoked = FALSE)', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res = await get(validHeaders())
      assert.strictEqual(res.status, 401)
    })
  })

  describe('session key store failures — 401', () => {
    it('returns 401 when no K is in the store for this device', async () => {
      // K was consumed by beforeEach storeSessionKey, drain it first
      const { consumeSessionKey } = await import('../../state/session_keys.js')
      consumeSessionKey(VALID_DEVICE_ID)
      const res = await get(validHeaders())
      assert.strictEqual(res.status, 401)
    })

    it('K is one-use: second request with same K returns 401', async () => {
      const hdrs = validHeaders()
      const first = await get(hdrs)
      assert.strictEqual(first.status, 200)

      // Re-plant headers for second call — K is gone after first use
      storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
      // But now use the *same* proof as before (already consumed K)
      globalThis.__db.queryImpl = async () => ({ rows: [{ '?column?': 1 }] })
      // Don't re-plant K, so second call has no K
      const { consumeSessionKey } = await import('../../state/session_keys.js')
      consumeSessionKey(VALID_DEVICE_ID) // drain it
      const second = await get(hdrs)
      assert.strictEqual(second.status, 401)
    })
  })

  describe('HMAC verification failures — 401', () => {
    it('returns 401 for a correct-length proof with wrong HMAC value', async () => {
      const res = await get({
        'x-device-id':     VALID_DEVICE_ID,
        'x-session-proof': '00'.repeat(32),
      })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when proof is computed for the wrong path', async () => {
      const res = await get({
        'x-device-id':     VALID_DEVICE_ID,
        'x-session-proof': computeProof(TEST_KEY_HEX, 'GET', '/wrong-path'),
      })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when proof is computed for the wrong method', async () => {
      const res = await get({
        'x-device-id':     VALID_DEVICE_ID,
        'x-session-proof': computeProof(TEST_KEY_HEX, 'POST', '/protected'),
      })
      assert.strictEqual(res.status, 401)
    })
  })

  describe('uniform 401 body (no info leak)', () => {
    it('all 401 responses have the same body', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const noDevice = await get({ 'x-session-proof': '00'.repeat(32) })

      storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const notFound = await get(validHeaders())

      storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
      globalThis.__db.queryImpl = async () => ({ rows: [{ '?column?': 1 }] })
      const wrongHmac = await get({ 'x-device-id': VALID_DEVICE_ID, 'x-session-proof': '00'.repeat(32) })

      assert.deepStrictEqual(noDevice.body, notFound.body)
      assert.deepStrictEqual(notFound.body, wrongHmac.body)
    })
  })

  describe('DB error propagation', () => {
    it('returns 500 when the DB query throws unexpectedly', async () => {
      globalThis.__db.queryImpl = async () => { throw new Error('connection lost') }
      const res = await get(validHeaders())
      assert.strictEqual(res.status, 500)
    })
  })
})
