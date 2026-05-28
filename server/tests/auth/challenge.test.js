import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { challenge } from '../../handlers/auth/challenge.js'

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/challenge', challenge)
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

let server
let baseUrl

before(() => new Promise(resolve => {
  server = createApp().listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`
    resolve()
  })
}))

after(() => new Promise(resolve => server.close(resolve)))

// Helpers
function mockQuery(rows) {
  globalThis.__db.queryImpl = async () => ({ rows })
}
function mockQueryThrow(err) {
  globalThis.__db.queryImpl = async () => { throw err }
}

async function post(body) {
  const res = await fetch(`${baseUrl}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  globalThis.__db.queryImpl = null
})

describe('POST /auth/challenge', () => {
  describe('device_id validation', () => {
    const invalidCases = [
      [undefined, 'missing'],
      [null,      'null'],
      [0,         'number zero'],
      [42,        'number'],
      [{},        'object'],
      [[],        'array'],
      [true,      'boolean'],
      ['',        'empty string'],
    ]

    for (const [device_id, desc] of invalidCases) {
      it(`returns 400 for device_id: ${desc}`, async () => {
        const res = await post({ device_id })
        assert.strictEqual(res.status, 400)
        assert.strictEqual(res.body.error, 'Invalid device_id')
      })
    }
  })

  describe('device lookup', () => {
    it('returns 401 when device is not found', async () => {
      mockQuery([])
      const res = await post({ device_id: 'nonexistent-id' })
      assert.strictEqual(res.status, 401)
      assert.strictEqual(res.body.error, 'Authentication failed')
    })

    it('queries DB with parameterised query (not string concat)', async () => {
      let captured = null
      globalThis.__db.queryImpl = async (text, params) => {
        captured = { text, params }
        return { rows: [] }
      }
      await post({ device_id: 'some-id' })
      assert.ok(captured.text.includes('$1'), 'SQL must use $1 parameter')
      assert.ok(Array.isArray(captured.params) && captured.params.includes('some-id'))
    })
  })

  describe('oracle prevention', () => {
    it('device-not-found and revoked-device return identical error bodies', async () => {
      mockQuery([])
      const res1 = await post({ device_id: 'id-a' })

      mockQuery([])
      const res2 = await post({ device_id: 'id-b' })

      assert.strictEqual(res1.status, res2.status)
      assert.deepStrictEqual(res1.body, res2.body)
    })

    it('error message does not reveal whether device exists', async () => {
      mockQuery([])
      const res = await post({ device_id: 'some-id' })
      assert.doesNotMatch(res.body.error, /not found/i)
      assert.doesNotMatch(res.body.error, /revok/i)
      assert.doesNotMatch(res.body.error, /device/i)
    })
  })

  describe('DB error propagation', () => {
    it('returns 500 on unexpected DB error', async () => {
      mockQueryThrow(new Error('connection error'))
      const res = await post({ device_id: 'some-id' })
      assert.strictEqual(res.status, 500)
    })
  })
})
