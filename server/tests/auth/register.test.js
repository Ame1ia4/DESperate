import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'
import { randomBytes } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { generateKeyBundle, validDeviceBody, zeroHex, randomHex } from '../helpers/keyFixtures.js'
import {
  X25519_PUB_BYTES, SIGNING_PUB_BYTES, DUAL_SIG_BYTES,
  MLKEM_PUB_BYTES, ED25519_SIG_BYTES,
  ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM,
} from '../../constants/auth.js'

vi.mock('argon2', () => ({
  default: {
    hash: vi.fn().mockResolvedValue('$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash'),
    argon2id: 2,
  },
}))

vi.mock('../../database/db.js', () => ({
  query:           vi.fn(),
  withTransaction: vi.fn(),
}))

import argon2 from 'argon2'
import * as db from '../../database/db.js'
import { register } from '../../handlers/auth/register.js'

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/register', register)
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

let bundle
let app

beforeAll(async () => {
  bundle = generateKeyBundle()
  app = createApp()
})

beforeEach(() => {
  vi.clearAllMocks()

  // Default happy-path DB mocks
  db.query.mockResolvedValue({ rows: [] }) // username not taken
  db.withTransaction.mockImplementation(async (fn) => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({ rows: [{ id: 'user-uuid' }] })    // INSERT user
        .mockResolvedValueOnce({ rows: [{ id: 'device-uuid' }] })  // INSERT device
        .mockResolvedValueOnce({ rows: [] }),                       // INSERT OPKs
    }
    return fn(client)
  })
})

const validBody = () => ({
  username: 'testuser',
  password: 'securePassword123',
  device: validDeviceBody(bundle),
})

describe('POST /auth/register', () => {
  describe('happy path', () => {
    it('returns 201 with deviceId for a valid registration', async () => {
      const res = await request(app).post('/auth/register').send(validBody())
      expect(res.status).toBe(201)
      expect(res.body).toHaveProperty('deviceId', 'device-uuid')
    })

    it('accepts registration without optional fields (no idk_pq_pub, no last-resort OPK, empty opks)', async () => {
      const body = validBody()
      delete body.device.idk_pq_pub
      delete body.device.last_resort_opk_pub
      delete body.device.last_resort_opk_signature
      body.device.opks = []
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(201)
    })

    it('accepts a device_name within length limit', async () => {
      const body = validBody()
      body.device.device_name = 'My Device'
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(201)
    })

    it('calls argon2.hash with correct OWASP parameters', async () => {
      await request(app).post('/auth/register').send(validBody())
      expect(argon2.hash).toHaveBeenCalledWith('securePassword123', {
        type:        argon2.argon2id,
        memoryCost:  ARGON2_MEMORY_COST,
        timeCost:    ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
      })
    })
  })

  describe('username validation', () => {
    const cases = [
      [undefined,            'missing'],
      [null,                 'null'],
      [42,                   'number type'],
      ['ab',                 'too short (2 chars)'],
      ['a'.repeat(51),       'too long (51 chars)'],
      ["admin'--",           'SQL injection attempt'],
      ['<script>alert</script>', 'XSS attempt'],
      ['user name',          'contains space'],
      ['ñaméé',              'non-ASCII unicode'],
      ['user@domain',        'contains @'],
      ['user!',              'contains !'],
      ['',                   'empty string'],
    ]

    for (const [username, desc] of cases) {
      it(`rejects username: ${desc}`, async () => {
        const body = { ...validBody(), username }
        const res = await request(app).post('/auth/register').send(body)
        expect(res.status).toBe(400)
        expect(res.body.error).toBe('Invalid username')
      })
    }

    it('accepts username at minimum length (3 chars)', async () => {
      const body = { ...validBody(), username: 'abc' }
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(201)
    })

    it('accepts username at maximum length (50 chars)', async () => {
      const body = { ...validBody(), username: 'a'.repeat(50) }
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(201)
    })
  })

  describe('password validation', () => {
    const cases = [
      [undefined,              'missing'],
      [null,                   'null'],
      [42,                     'number type'],
      ['tooshort11',           'too short (11 chars)'],
      ['',                     'empty string'],
    ]

    for (const [password, desc] of cases) {
      it(`rejects password: ${desc}`, async () => {
        const body = { ...validBody(), password }
        const res = await request(app).post('/auth/register').send(body)
        expect(res.status).toBe(400)
        expect(res.body.error).toBe('Invalid password')
      })
    }

    it('accepts password at minimum length (12 chars)', async () => {
      const body = { ...validBody(), password: 'a'.repeat(12) }
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(201)
    })
  })

  describe('device object validation', () => {
    it('rejects missing device', async () => {
      const { device: _, ...body } = validBody()
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid device')
    })

    it('rejects device = null', async () => {
      const res = await request(app).post('/auth/register').send({ ...validBody(), device: null })
      expect(res.status).toBe(400)
    })

    it('rejects device = array', async () => {
      const res = await request(app).post('/auth/register').send({ ...validBody(), device: [] })
      expect(res.status).toBe(400)
    })

    it('rejects device = string', async () => {
      const res = await request(app).post('/auth/register').send({ ...validBody(), device: 'bad' })
      expect(res.status).toBe(400)
    })

    it('rejects device_name longer than 100 chars', async () => {
      const body = validBody()
      body.device.device_name = 'x'.repeat(101)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid device_name')
    })

    it('accepts device_name = null (treated as absent)', async () => {
      const body = validBody()
      body.device.device_name = null
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(201)
    })
  })

  describe('key material size attacks', () => {
    it('rejects idk_classical_pub that is one byte short', async () => {
      const body = validBody()
      body.device.idk_classical_pub = randomHex(X25519_PUB_BYTES - 1)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/idk_classical_pub/)
    })

    it('rejects idk_classical_pub with non-hex chars', async () => {
      const body = validBody()
      body.device.idk_classical_pub = 'z'.repeat(X25519_PUB_BYTES * 2)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
    })

    it('rejects identity_signing_pub with wrong total length', async () => {
      const body = validBody()
      body.device.identity_signing_pub = randomHex(SIGNING_PUB_BYTES - 1)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/identity_signing_pub/)
    })

    it('rejects signed_prekey_pub with wrong length', async () => {
      const body = validBody()
      body.device.signed_prekey_pub = randomHex(X25519_PUB_BYTES + 1)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
    })

    it('rejects signed_prekey_signature with wrong length', async () => {
      const body = validBody()
      body.device.signed_prekey_signature = randomHex(DUAL_SIG_BYTES - 1)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
    })

    it('rejects idk_pq_pub with wrong length when provided', async () => {
      const body = validBody()
      body.device.idk_pq_pub = randomHex(MLKEM_PUB_BYTES - 1)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/idk_pq_pub/)
    })

    it('rejects when last_resort_opk_pub is provided but last_resort_opk_signature is null', async () => {
      const body = validBody()
      body.device.last_resort_opk_pub = randomHex(X25519_PUB_BYTES)
      body.device.last_resort_opk_signature = null
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
    })

    it('rejects opks array with 101 entries', async () => {
      const body = validBody()
      body.device.opks = Array.from({ length: 101 }, () => randomHex(X25519_PUB_BYTES))
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid opks')
    })

    it('rejects an opk entry with invalid hex', async () => {
      const body = validBody()
      body.device.opks = ['z'.repeat(X25519_PUB_BYTES * 2)]
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
    })

    it('rejects opks when not an array', async () => {
      const body = validBody()
      body.device.opks = 'notanarray'
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid opks')
    })
  })

  describe('signature verification attacks', () => {
    it('rejects signed_prekey_signature of all zeros (valid length, invalid sig)', async () => {
      const body = validBody()
      body.device.signed_prekey_signature = zeroHex(DUAL_SIG_BYTES)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects signed_prekey_signature of random bytes (valid length)', async () => {
      const body = validBody()
      body.device.signed_prekey_signature = randomHex(DUAL_SIG_BYTES)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects sig signed over a different message (not the SPK pub)', async () => {
      const body = validBody()
      const wrongMsg   = randomBytes(32)
      const ed25519Sig = Buffer.from(ed25519.sign(wrongMsg, bundle.ed25519PrivKey))
      const mlDsaSig   = Buffer.from(ml_dsa65.sign(wrongMsg, bundle.mlDsaSecKey))
      body.device.signed_prekey_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects sig signed with a different (unrelated) keypair', async () => {
      const body = validBody()
      const otherPriv    = randomBytes(32)
      const otherSeed    = randomBytes(32)
      const { secretKey: otherMlSec } = ml_dsa65.keygen(otherSeed)
      const spkPub       = Buffer.from(body.device.signed_prekey_pub, 'hex')
      const ed25519Sig   = Buffer.from(ed25519.sign(spkPub, otherPriv))
      const mlDsaSig     = Buffer.from(ml_dsa65.sign(spkPub, otherMlSec))
      body.device.signed_prekey_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects when only the ML-DSA half of the signature is valid (ed25519 is zeros)', async () => {
      const body = validBody()
      const spkPub   = Buffer.from(body.device.signed_prekey_pub, 'hex')
      const zeroEd   = Buffer.alloc(ED25519_SIG_BYTES)
      const mlDsaSig = Buffer.from(ml_dsa65.sign(spkPub, bundle.mlDsaSecKey))
      body.device.signed_prekey_signature = Buffer.concat([zeroEd, mlDsaSig]).toString('hex')
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects when only the ed25519 half of the signature is valid (ml_dsa is zeros)', async () => {
      const body = validBody()
      const spkPub     = Buffer.from(body.device.signed_prekey_pub, 'hex')
      const ed25519Sig = Buffer.from(ed25519.sign(spkPub, bundle.ed25519PrivKey))
      const zeroMl     = Buffer.alloc(DUAL_SIG_BYTES - ED25519_SIG_BYTES)
      body.device.signed_prekey_signature = Buffer.concat([ed25519Sig, zeroMl]).toString('hex')
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects last-resort OPK sig when tampered (all zeros)', async () => {
      const body = validBody()
      const lrOpkPub = randomBytes(32)
      body.device.last_resort_opk_pub       = lrOpkPub.toString('hex')
      body.device.last_resort_opk_signature = zeroHex(DUAL_SIG_BYTES)
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })

    it('rejects last-resort OPK sig signed over a different message', async () => {
      const body = validBody()
      const lrOpkPub   = randomBytes(32)
      const wrongMsg   = randomBytes(32)
      const ed25519Sig = Buffer.from(ed25519.sign(wrongMsg, bundle.ed25519PrivKey))
      const mlDsaSig   = Buffer.from(ml_dsa65.sign(wrongMsg, bundle.mlDsaSecKey))
      body.device.last_resort_opk_pub       = lrOpkPub.toString('hex')
      body.device.last_resort_opk_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await request(app).post('/auth/register').send(body)
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Invalid key bundle')
    })
  })

  describe('username collision (timing-safe, oracle prevention)', () => {
    it('returns 409 when username is already taken', async () => {
      db.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] }) // username exists
      const res = await request(app).post('/auth/register').send(validBody())
      expect(res.status).toBe(409)
      expect(res.body.error).toBe('Registration failed')
    })

    it('still calls argon2.hash even when username is taken (timing-safe)', async () => {
      db.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] })
      await request(app).post('/auth/register').send(validBody())
      expect(argon2.hash).toHaveBeenCalledOnce()
    })

    it('returns 409 on DB unique constraint violation (code 23505)', async () => {
      const innerErr = new Error('duplicate key value violates unique constraint')
      innerErr.code = '23505'
      const wrapErr = new Error('Transaction failed')
      wrapErr.cause = innerErr
      db.withTransaction.mockRejectedValueOnce(wrapErr)
      const res = await request(app).post('/auth/register').send(validBody())
      expect(res.status).toBe(409)
      expect(res.body.error).toBe('Registration failed')
    })

    it('username-taken and DB-constraint-violation return identical JSON bodies (no enumeration)', async () => {
      db.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] })
      const res1 = await request(app).post('/auth/register').send(validBody())

      vi.clearAllMocks()
      db.query.mockResolvedValue({ rows: [] })
      const innerErr = new Error('duplicate key')
      innerErr.code = '23505'
      const wrapErr = new Error('Transaction failed')
      wrapErr.cause = innerErr
      db.withTransaction.mockRejectedValueOnce(wrapErr)
      const res2 = await request(app).post('/auth/register').send(validBody())

      expect(res1.body).toEqual(res2.body)
    })

    it('does not expose whether the username exists in the error message', async () => {
      db.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] })
      const res = await request(app).post('/auth/register').send(validBody())
      expect(res.body.error).not.toMatch(/username/i)
      expect(res.body.error).not.toMatch(/taken/i)
      expect(res.body.error).not.toMatch(/exist/i)
    })
  })

  describe('DB error propagation', () => {
    it('returns 500 on unexpected DB error (not rethrown as 409)', async () => {
      const unexpectedErr = new Error('connection refused')
      db.withTransaction.mockRejectedValueOnce(unexpectedErr)
      const res = await request(app).post('/auth/register').send(validBody())
      expect(res.status).toBe(500)
    })
  })
})
