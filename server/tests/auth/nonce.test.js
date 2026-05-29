import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { issueNonce, consumeNonce, registrationNonce } from '../../handlers/auth/nonce.js'

describe('nonce module', () => {
  describe('issueNonce()', () => {
    it('returns a 64-character hex string (32 bytes)', () => {
      const nonce = issueNonce()
      assert.strictEqual(typeof nonce, 'string')
      assert.strictEqual(nonce.length, 64)
      assert.match(nonce, /^[0-9a-f]+$/i)
    })

    it('returns a different nonce on each call', () => {
      const a = issueNonce()
      const b = issueNonce()
      assert.notStrictEqual(a, b)
    })
  })

  describe('consumeNonce()', () => {
    it('returns true for a valid issued nonce', () => {
      const nonce = issueNonce()
      assert.strictEqual(consumeNonce(nonce), true)
    })

    it('returns false on the second call with the same nonce (single-use)', () => {
      const nonce = issueNonce()
      consumeNonce(nonce)
      assert.strictEqual(consumeNonce(nonce), false)
    })

    it('returns false for an unknown nonce', () => {
      assert.strictEqual(consumeNonce('00'.repeat(32)), false)
    })

    it('returns false for non-string input without throwing', () => {
      assert.strictEqual(consumeNonce(null), false)
      assert.strictEqual(consumeNonce(undefined), false)
      assert.strictEqual(consumeNonce(42), false)
    })
  })
})

describe('GET /auth/nonce', () => {
  let server, baseUrl

  before(() => new Promise(resolve => {
    const app = express()
    app.get('/auth/nonce', registrationNonce)
    server = app.listen(0, () => {
      baseUrl = `http://localhost:${server.address().port}`
      resolve()
    })
  }))

  after(() => new Promise(resolve => server.close(resolve)))

  it('returns 200 with a nonce field', async () => {
    const res = await fetch(`${baseUrl}/auth/nonce`)
    assert.strictEqual(res.status, 200)
    const body = await res.json()
    assert.ok('nonce' in body)
  })

  it('nonce is a 64-character hex string', async () => {
    const res  = await fetch(`${baseUrl}/auth/nonce`)
    const body = await res.json()
    assert.strictEqual(body.nonce.length, 64)
    assert.match(body.nonce, /^[0-9a-f]+$/i)
  })

  it('returned nonce is consumable (was actually issued)', async () => {
    const res  = await fetch(`${baseUrl}/auth/nonce`)
    const body = await res.json()
    assert.strictEqual(consumeNonce(body.nonce), true)
  })

  it('each request returns a different nonce', async () => {
    const [r1, r2] = await Promise.all([
      fetch(`${baseUrl}/auth/nonce`).then(r => r.json()),
      fetch(`${baseUrl}/auth/nonce`).then(r => r.json()),
    ])
    assert.notStrictEqual(r1.nonce, r2.nonce)
  })
})
