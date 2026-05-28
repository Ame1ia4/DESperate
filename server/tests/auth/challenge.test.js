import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'

vi.mock('../../database/db.js', () => ({
  query:           vi.fn(),
  withTransaction: vi.fn(),
}))

import * as db from '../../database/db.js'
import { challenge } from '../../handlers/auth/challenge.js'

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/challenge', challenge)
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

const app = createApp()

beforeEach(() => {
  vi.clearAllMocks()
})

describe('POST /auth/challenge', () => {
  describe('device_id validation', () => {
    const invalidCases = [
      [undefined,  'missing'],
      [null,       'null'],
      [0,          'number zero'],
      [42,         'number'],
      [{},         'object'],
      [[],         'array'],
      [true,       'boolean'],
      ['',         'empty string'],
    ]

    for (const [device_id, desc] of invalidCases) {
      it(`returns 400 for device_id: ${desc}`, async () => {
        const res = await request(app).post('/auth/challenge').send({ device_id })
        expect(res.status).toBe(400)
        expect(res.body.error).toBe('Invalid device_id')
      })
    }
  })

  describe('device lookup', () => {
    it('returns 401 when device is not found', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      const res = await request(app).post('/auth/challenge').send({ device_id: 'nonexistent-id' })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 when device is revoked (filtered by WHERE revoked = FALSE)', async () => {
      // The query uses `WHERE id = $1 AND revoked = FALSE` — revoked device returns no rows
      db.query.mockResolvedValueOnce({ rows: [] })
      const res = await request(app).post('/auth/challenge').send({ device_id: 'revoked-device-id' })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('returns 401 even when device is found (nonce creation is not yet implemented)', async () => {
      // The challenge handler is a stub — it always returns 401 pending sessions.js
      db.query.mockResolvedValueOnce({ rows: [{ id: 'device-uuid' }] })
      const res = await request(app).post('/auth/challenge').send({ device_id: 'valid-device-id' })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Authentication failed')
    })

    it('queries DB with parameterised query (not string concat)', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      await request(app).post('/auth/challenge').send({ device_id: 'some-id' })
      expect(db.query).toHaveBeenCalledWith(
        expect.stringContaining('$1'),
        expect.arrayContaining(['some-id'])
      )
    })
  })

  describe('oracle prevention', () => {
    it('device-not-found and revoked-device return identical error bodies', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      const res1 = await request(app).post('/auth/challenge').send({ device_id: 'id-a' })

      db.query.mockResolvedValueOnce({ rows: [] }) // same result — revoked filtered out
      const res2 = await request(app).post('/auth/challenge').send({ device_id: 'id-b' })

      expect(res1.body).toEqual(res2.body)
      expect(res1.status).toBe(res2.status)
    })

    it('error message does not reveal whether device exists', async () => {
      db.query.mockResolvedValueOnce({ rows: [] })
      const res = await request(app).post('/auth/challenge').send({ device_id: 'some-id' })
      expect(res.body.error).not.toMatch(/not found/i)
      expect(res.body.error).not.toMatch(/revok/i)
      expect(res.body.error).not.toMatch(/device/i)
    })
  })

  describe('DB error propagation', () => {
    it('returns 500 on unexpected DB error', async () => {
      db.query.mockRejectedValueOnce(new Error('connection error'))
      const res = await request(app).post('/auth/challenge').send({ device_id: 'some-id' })
      expect(res.status).toBe(500)
    })
  })
})
