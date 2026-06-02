// Tests for the requireSrpSession middleware (test matrix #10).
// Covers: missing header, expired session, revoked device, valid session.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { requireSrpSession } from '../../middleware/requireSrpSession.js'

const DEVICE_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
const USER_ID   = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'

function makeApp() {
  const app = express()
  app.use(express.json())
  app.get('/protected', requireSrpSession, (req, res) => {
    res.json({ deviceId: req.deviceId, userId: req.userId })
  })
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
  globalThis.__db.queryImpl = null
  globalThis.__db.clientQueryResults = []
})

function validDevice(overrides = {}) {
  return {
    user_id:         USER_ID,
    revoked:         false,
    srp_verified_at: new Date(Date.now() - 60_000).toISOString(),
    srp_expires_at:  new Date(Date.now() + 3_600_000).toISOString(),
    ...overrides,
  }
}

async function get(headers = {}) {
  return fetch(`${baseUrl}/protected`, { headers })
}

describe('requireSrpSession()', () => {
  it('returns 401 when x-device-id header is missing', async () => {
    globalThis.__db.queryImpl = async () => { throw new Error('must not query') }
    const res = await get()
    assert.strictEqual(res.status, 401)
  })

  it('returns 401 when x-device-id is not a valid UUID', async () => {
    globalThis.__db.queryImpl = async () => { throw new Error('must not query') }
    const res = await get({ 'x-device-id': 'not-a-uuid' })
    assert.strictEqual(res.status, 401)
  })

  it('returns 401 when device is not found', async () => {
    globalThis.__db.queryImpl = async () => ({ rows: [] })
    const res = await get({ 'x-device-id': DEVICE_ID })
    assert.strictEqual(res.status, 401)
  })

  it('returns 401 when device is revoked', async () => {
    globalThis.__db.queryImpl = async () => ({ rows: [validDevice({ revoked: true })] })
    const res = await get({ 'x-device-id': DEVICE_ID })
    assert.strictEqual(res.status, 401)
    const json = await res.json()
    assert.match(json.error, /revoked/)
  })

  it('returns 401 when srp_verified_at is null (session not established)', async () => {
    globalThis.__db.queryImpl = async () => ({
      rows: [validDevice({ srp_verified_at: null, srp_expires_at: null })],
    })
    const res = await get({ 'x-device-id': DEVICE_ID })
    assert.strictEqual(res.status, 401)
  })

  it('returns 401 when session is expired', async () => {
    globalThis.__db.queryImpl = async () => ({
      rows: [validDevice({ srp_expires_at: new Date(Date.now() - 1000).toISOString() })],
    })
    const res = await get({ 'x-device-id': DEVICE_ID })
    assert.strictEqual(res.status, 401)
    const json = await res.json()
    assert.match(json.error, /expired/)
  })

  it('calls next and sets req.deviceId + req.userId for a valid unexpired session', async () => {
    globalThis.__db.queryImpl = async () => ({ rows: [validDevice()] })
    const res  = await get({ 'x-device-id': DEVICE_ID })
    assert.strictEqual(res.status, 200)
    const json = await res.json()
    assert.strictEqual(json.deviceId, DEVICE_ID)
    assert.strictEqual(json.userId, USER_ID)
  })
})
