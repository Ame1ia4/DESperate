import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { requireAuth } from '../../middleware/require_auth.js'
import { storeSessionKey } from '../../state/session_keys.js'

const VALID_DEVICE_ID  = 'cccccccc-cccc-4ccc-cccc-cccccccccccc'
const UNKNOWN_DEVICE_ID = 'dddddddd-dddd-4ddd-dddd-dddddddddddd'
// 32-byte session key represented as 64 hex chars (SRP-derived K size)
const TEST_KEY_HEX = 'abcdef01'.repeat(8)

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

// Default: active unrevoked device in DB, K planted in store.
// queryImpl must be set before storeSessionKey because the INSERT awaits pool.query().
beforeEach(async () => {
  globalThis.__db.queryImpl = async () => ({ rows: [{ '?column?': 1 }] })
  await storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
})

async function get(headers = {}) {
  const res = await fetch(`${baseUrl}/protected`, { headers })
  return { status: res.status, body: await res.json() }
}

function validHeaders() {
  return {
    'x-device-id':   VALID_DEVICE_ID,
    'authorization': `Bearer ${TEST_KEY_HEX}`,
  }
}

describe('requireAuth middleware', () => {
  describe('happy path', () => {
    it('passes through to the route handler when device is active and token is valid', async () => {
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
      const res = await get({ 'authorization': `Bearer ${TEST_KEY_HEX}` })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a non-UUID X-Device-ID', async () => {
      const res = await get({ 'x-device-id': 'not-a-uuid', 'authorization': `Bearer ${TEST_KEY_HEX}` })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when Authorization header is absent', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when Authorization is not a Bearer token', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID, 'authorization': TEST_KEY_HEX })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a non-hex bearer token', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID, 'authorization': 'Bearer not-hex-!!' })
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
      // Use a device that never had a key stored — cache miss, DB fallback returns empty
      globalThis.__db.queryImpl = async (sql) => {
        if (sql.includes('device_sessions')) return { rows: [] }
        return { rows: [{ '?column?': 1 }] }  // devices check passes
      }
      const res = await get({
        'x-device-id':   UNKNOWN_DEVICE_ID,
        'authorization': `Bearer ${TEST_KEY_HEX}`,
      })
      assert.strictEqual(res.status, 401)
    })
  })

  describe('wrong token value — 401', () => {
    it('returns 401 when bearer token does not match the stored session key', async () => {
      const res = await get({
        'x-device-id':   VALID_DEVICE_ID,
        'authorization': `Bearer ${'00'.repeat(32)}`,
      })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a different valid-length hex token', async () => {
      const res = await get({
        'x-device-id':   VALID_DEVICE_ID,
        'authorization': `Bearer ${'ff'.repeat(32)}`,
      })
      assert.strictEqual(res.status, 401)
    })
  })

  describe('uniform 401 body (no info leak)', () => {
    it('all 401 responses have the same body', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const noDevice = await get({ 'authorization': `Bearer ${TEST_KEY_HEX}` })

      await storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const notFound = await get(validHeaders())

      await storeSessionKey(VALID_DEVICE_ID, TEST_KEY_HEX)
      globalThis.__db.queryImpl = async () => ({ rows: [{ '?column?': 1 }] })
      const wrongToken = await get({
        'x-device-id':   VALID_DEVICE_ID,
        'authorization': `Bearer ${'00'.repeat(32)}`,
      })

      assert.deepStrictEqual(noDevice.body, notFound.body)
      assert.deepStrictEqual(notFound.body, wrongToken.body)
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
