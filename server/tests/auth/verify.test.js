import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'
import { randomBytes } from 'node:crypto'
import { zeroHex, randomHex } from '../helpers/keyFixtures.js'
import { ED25519_SIG_BYTES, MLDSA_SIG_BYTES } from '../../constants/auth.js'

vi.mock('../../database/db.js', () => ({
  query:           vi.fn(),
  withTransaction: vi.fn(),
}))

vi.mock('../../sessions.js', () => ({
  createSession:                vi.fn().mockReturnValue('test-session-token'),
  consumeChallenge:             vi.fn(),
  deleteSession:                vi.fn(),
  deleteAllSessionsForDevice:   vi.fn(),
}))

import * as db from '../../database/db.js'
import { verify } from '../../handlers/auth/verify.js'

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/verify', verify)
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

const app = createApp()

const validSigs = () => ({
  ed25519_sig: randomHex(ED25519_SIG_BYTES),
  ml_dsa_sig:  randomHex(MLDSA_SIG_BYTES),
})

beforeEach(() => {
  vi.clearAllMocks()
})

describe('POST /auth/verify', () => {
  describe('device_id validation', () => {
    const invalidCases = [
      [undefined,  'missing'],
      [null,       'null'],
      [0,          'number'],
      [{},         'object'],
      [[],         'array'],
      ['',         'empty string'],
    ]

    for (const [device_id, desc] of invalidCases) {
      it(`returns 400 for device_id: ${desc}`, async () => {
        const res = await request(app).post('/auth/verify').send({ device_id, ...validSigs() })
        expect(res.status).toBe(400)
        expect(res.body.error).toBe('Invalid device_id')
      })
    }
  })

  describe('malformed signature oracle prevention', () => {
    // Malformed sigs must return 401 (not 400) to prevent distinguishing
    // "bad format" from "valid format, wrong key" — an oracle attack vector.

    it('returns 401 (not 400) when ed25519_sig is too short', async () => {
      const res = await request(app).post('/auth/verify').send({
        device_id: 'some-id',
        ed25519_sig: randomHex(ED25519_SIG_BYTES - 1),
        ml_dsa_sig:  randomHex(MLDSA_SIG_BYTES),
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when ed25519_sig contains non-hex chars', async () => {
      const res = await request(app).post('/auth/verify').send({
        device_id:   'some-id',
        ed25519_sig: 'z'.repeat(ED25519_SIG_BYTES * 2),
        ml_dsa_sig:  randomHex(MLDSA_SIG_BYTES),
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when ml_dsa_sig is too short', async () => {
      const res = await request(app).post('/auth/verify').send({
        device_id:   'some-id',
        ed25519_sig: randomHex(ED25519_SIG_BYTES),
        ml_dsa_sig:  randomHex(MLDSA_SIG_BYTES - 1),
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when ml_dsa_sig contains non-hex chars', async () => {
      const res = await request(app).post('/auth/verify').send({
        device_id:   'some-id',
        ed25519_sig: randomHex(ED25519_SIG_BYTES),
        ml_dsa_sig:  'z'.repeat(MLDSA_SIG_BYTES * 2),
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when both sigs are malformed', async () => {
      const res = await request(app).post('/auth/verify').send({
        device_id:   'some-id',
        ed25519_sig: 'bad',
        ml_dsa_sig:  'bad',
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when sigs are missing entirely', async () => {
      const res = await request(app).post('/auth/verify').send({ device_id: 'some-id' })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('malformed-sig and device-not-found return identical error bodies (oracle prevention)', async () => {
      // Malformed sig path (catches before DB query)
      const resMalformed = await request(app).post('/auth/verify').send({
        device_id:   'some-id',
        ed25519_sig: 'tooshort',
        ml_dsa_sig:  randomHex(MLDSA_SIG_BYTES),
      })

      // Device-not-found path (DB returns empty)
      db.query.mockResolvedValueOnce({ rows: [] })
      const resNotFound = await request(app).post('/auth/verify').send({
        device_id:   'some-id',
        ...validSigs(),
      })

      expect(resMalformed.status).toBe(resNotFound.status)
      expect(resMalformed.body).toEqual(resNotFound.body)
    })
  })

  describe('device lookup', () => {
    it('returns 401 when device is not found', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      const res = await request(app).post('/auth/verify').send({
        device_id: 'nonexistent',
        ...validSigs(),
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when device is revoked (filtered by WHERE revoked = FALSE)', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      const res = await request(app).post('/auth/verify').send({
        device_id: 'revoked-device',
        ...validSigs(),
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('queries DB with parameterised query', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      await request(app).post('/auth/verify').send({ device_id: 'test-id', ...validSigs() })
      expect(db.query).toHaveBeenCalledWith(
        expect.stringContaining('$1'),
        expect.arrayContaining(['test-id'])
      )
    })
  })

  describe('post-device-lookup behavior (known gap: nonce undefined)', () => {
    // verify.js line 40 references `nonce` which is undefined (TODO: pending sessions.js).
    // When a device IS found, the handler throws a ReferenceError before signature
    // verification. The global error handler returns 500 with a generic message.
    // This documents the known gap — tests will be expanded when sessions.js lands.

    it('does not leak internal error details when nonce is undefined (returns generic 500)', async () => {
      db.query
        .mockResolvedValueOnce({ rows: [{ id: 'dev-id', user_id: 'user-id', identity_signing_pub: Buffer.alloc(100) }] })
        .mockResolvedValueOnce({ rows: [] })  // UPDATE last_seen (may not be reached)
      const res = await request(app).post('/auth/verify').send({
        device_id: 'valid-device',
        ...validSigs(),
      })
      expect(res.status).toBe(500)
      expect(res.body.error).toBe('Internal server error')
      expect(JSON.stringify(res.body)).not.toMatch(/nonce/i)
      expect(JSON.stringify(res.body)).not.toMatch(/ReferenceError/i)
    })
  })

  describe('oracle prevention — error message consistency', () => {
    it('error messages do not reveal whether device exists', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      const res = await request(app).post('/auth/verify').send({ device_id: 'x', ...validSigs() })
      expect(res.body.error).not.toMatch(/not found/i)
      expect(res.body.error).not.toMatch(/revok/i)
      expect(res.body.error).not.toMatch(/device/i)
    })
  })
})
