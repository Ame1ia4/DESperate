import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { requireAuth } from '../../middleware/require_auth.js'

const VALID_DEVICE_ID = 'cccccccc-cccc-4ccc-cccc-cccccccccccc'

function createApp() {
  const app = express()
  app.use(express.json())
  // Protected stub — records req.deviceId if middleware passes
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

// Default: valid active unrevoked device
beforeEach(() => {
  globalThis.__db.queryImpl = async () => ({ rows: [{ '?column?': 1 }] })
})

async function get(headers = {}) {
  const res = await fetch(`${baseUrl}/protected`, { headers })
  return { status: res.status, body: await res.json() }
}

describe('requireAuth middleware', () => {
  describe('happy path', () => {
    it('passes through to the route handler when device is active', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 200)
    })

    it('sets req.deviceId so route handlers can use it', async () => {
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.body.deviceId, VALID_DEVICE_ID)
    })
  })

  describe('missing or invalid X-Device-ID — 401 before DB hit', () => {
    // These cases are rejected before any DB query so queryImpl is not called.
    beforeEach(() => {
      globalThis.__db.queryImpl = async () => { throw new Error('Should not reach DB') }
    })

    it('returns 401 when X-Device-ID header is absent', async () => {
      const res = await get()
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for an empty X-Device-ID header', async () => {
      const res = await get({ 'x-device-id': '' })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a non-UUID string', async () => {
      const res = await get({ 'x-device-id': 'not-a-uuid' })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for a UUID with wrong structure', async () => {
      const res = await get({ 'x-device-id': 'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz' })
      assert.strictEqual(res.status, 401)
    })
  })

  describe('DB-level failures — 401', () => {
    it('returns 401 when device is not found in DB', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when srp_expires_at is in the past (expired session)', async () => {
      // The query filters WHERE srp_expires_at > NOW(); expired device returns no rows
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when device is revoked (filtered by WHERE revoked = FALSE)', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 401)
    })

    it('all 401 responses have the same body (no info leak between not-found, expired, revoked)', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res1 = await get({ 'x-device-id': VALID_DEVICE_ID })

      const res2 = await get() // missing header

      const res3 = await get({ 'x-device-id': 'bad-id' })

      assert.deepStrictEqual(res1.body, res2.body)
      assert.deepStrictEqual(res2.body, res3.body)
    })
  })

  describe('DB error propagation', () => {
    it('returns 500 when the DB query throws unexpectedly', async () => {
      globalThis.__db.queryImpl = async () => { throw new Error('connection lost') }
      const res = await get({ 'x-device-id': VALID_DEVICE_ID })
      assert.strictEqual(res.status, 500)
    })
  })
})
