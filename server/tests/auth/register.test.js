import { describe, it, before, after, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { randomBytes } from 'node:crypto'
import argon2 from 'argon2'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { generateKeyBundle, validDeviceBody, zeroHex, randomHex } from '../helpers/keyFixtures.js'
import {
  X25519_PUB_BYTES, SIGNING_PUB_BYTES, DUAL_SIG_BYTES,
  MLKEM_PUB_BYTES, ED25519_SIG_BYTES,
  ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM,
} from '../../constants/auth.js'
import { register } from '../../handlers/auth/register.js'

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/register', register)
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

let server
let baseUrl
let bundle
let argon2HashSpy

before(() => new Promise(resolve => {
  bundle = generateKeyBundle()
  server = createApp().listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`
    resolve()
  })
}))

after(() => new Promise(resolve => server.close(resolve)))

// Happy-path client query results: INSERT user → INSERT device → INSERT opks
const happyClientResults = () => [
  { rows: [{ id: 'user-uuid' }] },
  { rows: [{ id: 'device-uuid' }] },
  { rows: [] },
]

beforeEach(() => {
  mock.restoreAll()
  argon2HashSpy = mock.method(
    argon2, 'hash',
    async () => '$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash'
  )
  globalThis.__db.queryImpl          = async () => ({ rows: [] }) // username not taken
  globalThis.__db.clientQueryResults = happyClientResults()
})

async function post(body) {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

const validBody = () => ({
  username: 'testuser',
  password: 'securePassword123',
  device:   validDeviceBody(bundle),
})

describe('POST /auth/register', () => {
  describe('happy path', () => {
    it('returns 201 with deviceId for a valid registration', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.status, 201)
      assert.strictEqual(res.body.deviceId, 'device-uuid')
    })

    it('accepts registration without optional fields (no idk_pq_pub, no last-resort OPK, empty opks)', async () => {
      const body = validBody()
      delete body.device.idk_pq_pub
      delete body.device.last_resort_opk_pub
      delete body.device.last_resort_opk_signature
      body.device.opks = []
      // Empty opks means no OPK insert — only 2 client queries needed
      globalThis.__db.clientQueryResults = [
        { rows: [{ id: 'user-uuid' }] },
        { rows: [{ id: 'device-uuid' }] },
      ]
      const res = await post(body)
      assert.strictEqual(res.status, 201)
    })

    it('accepts a device_name within length limit', async () => {
      const body = validBody()
      body.device.device_name = 'My Device'
      const res = await post(body)
      assert.strictEqual(res.status, 201)
    })

    it('calls argon2.hash with correct OWASP parameters', async () => {
      await post(validBody())
      assert.strictEqual(argon2HashSpy.mock.calls.length, 1)
      assert.strictEqual(argon2HashSpy.mock.calls[0].arguments[0], 'securePassword123')
      assert.deepStrictEqual(argon2HashSpy.mock.calls[0].arguments[1], {
        type:        argon2.argon2id,
        memoryCost:  ARGON2_MEMORY_COST,
        timeCost:    ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
      })
    })
  })

  describe('username validation', () => {
    const cases = [
      [undefined,                'missing'],
      [null,                     'null'],
      [42,                       'number type'],
      ['ab',                     'too short (2 chars)'],
      ['a'.repeat(51),           'too long (51 chars)'],
      ["admin'--",               'SQL injection attempt'],
      ['<script>alert</script>', 'XSS attempt'],
      ['user name',              'contains space'],
      ['ñaméé',                  'non-ASCII unicode'],
      ['user@domain',            'contains @'],
      ['user!',                  'contains !'],
      ['',                       'empty string'],
    ]

    for (const [username, desc] of cases) {
      it(`rejects username: ${desc}`, async () => {
        const res = await post({ ...validBody(), username })
        assert.strictEqual(res.status, 400)
        assert.strictEqual(res.body.error, 'Invalid username')
      })
    }

    it('accepts username at minimum length (3 chars)', async () => {
      const res = await post({ ...validBody(), username: 'abc' })
      assert.strictEqual(res.status, 201)
    })

    it('accepts username at maximum length (50 chars)', async () => {
      const res = await post({ ...validBody(), username: 'a'.repeat(50) })
      assert.strictEqual(res.status, 201)
    })
  })

  describe('password validation', () => {
    const cases = [
      [undefined,    'missing'],
      [null,         'null'],
      [42,           'number type'],
      ['tooshort11', 'too short (11 chars)'],
      ['',           'empty string'],
    ]

    for (const [password, desc] of cases) {
      it(`rejects password: ${desc}`, async () => {
        const res = await post({ ...validBody(), password })
        assert.strictEqual(res.status, 400)
        assert.strictEqual(res.body.error, 'Invalid password')
      })
    }

    it('accepts password at minimum length (12 chars)', async () => {
      const res = await post({ ...validBody(), password: 'a'.repeat(12) })
      assert.strictEqual(res.status, 201)
    })
  })

  describe('device object validation', () => {
    it('rejects missing device', async () => {
      const { device: _, ...body } = validBody()
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid device')
    })

    it('rejects device = null', async () => {
      const res = await post({ ...validBody(), device: null })
      assert.strictEqual(res.status, 400)
    })

    it('rejects device = array', async () => {
      const res = await post({ ...validBody(), device: [] })
      assert.strictEqual(res.status, 400)
    })

    it('rejects device = string', async () => {
      const res = await post({ ...validBody(), device: 'bad' })
      assert.strictEqual(res.status, 400)
    })

    it('rejects device_name longer than 100 chars', async () => {
      const body = validBody()
      body.device.device_name = 'x'.repeat(101)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid device_name')
    })

    it('accepts device_name = null (treated as absent)', async () => {
      const body = validBody()
      body.device.device_name = null
      const res = await post(body)
      assert.strictEqual(res.status, 201)
    })
  })

  describe('key material size attacks', () => {
    it('rejects idk_classical_pub that is one byte short', async () => {
      const body = validBody()
      body.device.idk_classical_pub = randomHex(X25519_PUB_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.match(res.body.error, /idk_classical_pub/)
    })

    it('rejects idk_classical_pub with non-hex chars', async () => {
      const body = validBody()
      body.device.idk_classical_pub = 'z'.repeat(X25519_PUB_BYTES * 2)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects identity_signing_pub with wrong total length', async () => {
      const body = validBody()
      body.device.identity_signing_pub = randomHex(SIGNING_PUB_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.match(res.body.error, /identity_signing_pub/)
    })

    it('rejects signed_prekey_pub with wrong length', async () => {
      const body = validBody()
      body.device.signed_prekey_pub = randomHex(X25519_PUB_BYTES + 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects signed_prekey_signature with wrong length', async () => {
      const body = validBody()
      body.device.signed_prekey_signature = randomHex(DUAL_SIG_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects idk_pq_pub with wrong length when provided', async () => {
      const body = validBody()
      body.device.idk_pq_pub = randomHex(MLKEM_PUB_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.match(res.body.error, /idk_pq_pub/)
    })

    it('rejects when last_resort_opk_pub is provided but last_resort_opk_signature is null', async () => {
      const body = validBody()
      body.device.last_resort_opk_pub       = randomHex(X25519_PUB_BYTES)
      body.device.last_resort_opk_signature = null
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects opks array with 101 entries', async () => {
      const body = validBody()
      body.device.opks = Array.from({ length: 101 }, () => randomHex(X25519_PUB_BYTES))
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid opks')
    })

    it('rejects an opk entry with invalid hex', async () => {
      const body = validBody()
      body.device.opks = ['z'.repeat(X25519_PUB_BYTES * 2)]
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects opks when not an array', async () => {
      const body = validBody()
      body.device.opks = 'notanarray'
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid opks')
    })
  })

  describe('signature verification attacks', () => {
    it('rejects signed_prekey_signature of all zeros (valid length, invalid sig)', async () => {
      const body = validBody()
      body.device.signed_prekey_signature = zeroHex(DUAL_SIG_BYTES)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects signed_prekey_signature of random bytes (valid length)', async () => {
      const body = validBody()
      body.device.signed_prekey_signature = randomHex(DUAL_SIG_BYTES)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects sig signed over a different message (not the SPK pub)', async () => {
      const body       = validBody()
      const wrongMsg   = randomBytes(32)
      const ed25519Sig = Buffer.from(ed25519.sign(wrongMsg, bundle.ed25519PrivKey))
      const mlDsaSig   = Buffer.from(ml_dsa65.sign(wrongMsg, bundle.mlDsaSecKey))
      body.device.signed_prekey_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects sig signed with a different (unrelated) keypair', async () => {
      const body                      = validBody()
      const otherPriv                 = randomBytes(32)
      const { secretKey: otherMlSec } = ml_dsa65.keygen(randomBytes(32))
      const spkPub                    = Buffer.from(body.device.signed_prekey_pub, 'hex')
      const ed25519Sig                = Buffer.from(ed25519.sign(spkPub, otherPriv))
      const mlDsaSig                  = Buffer.from(ml_dsa65.sign(spkPub, otherMlSec))
      body.device.signed_prekey_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects when only the ML-DSA half of the signature is valid (ed25519 is zeros)', async () => {
      const body     = validBody()
      const spkPub   = Buffer.from(body.device.signed_prekey_pub, 'hex')
      const zeroEd   = Buffer.alloc(ED25519_SIG_BYTES)
      const mlDsaSig = Buffer.from(ml_dsa65.sign(spkPub, bundle.mlDsaSecKey))
      body.device.signed_prekey_signature = Buffer.concat([zeroEd, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects when only the ed25519 half of the signature is valid (ml_dsa is zeros)', async () => {
      const body       = validBody()
      const spkPub     = Buffer.from(body.device.signed_prekey_pub, 'hex')
      const ed25519Sig = Buffer.from(ed25519.sign(spkPub, bundle.ed25519PrivKey))
      const zeroMl     = Buffer.alloc(DUAL_SIG_BYTES - ED25519_SIG_BYTES)
      body.device.signed_prekey_signature = Buffer.concat([ed25519Sig, zeroMl]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects last-resort OPK sig when tampered (all zeros)', async () => {
      const body     = validBody()
      const lrOpkPub = randomBytes(32)
      body.device.last_resort_opk_pub       = lrOpkPub.toString('hex')
      body.device.last_resort_opk_signature = zeroHex(DUAL_SIG_BYTES)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects last-resort OPK sig signed over a different message', async () => {
      const body       = validBody()
      const lrOpkPub   = randomBytes(32)
      const wrongMsg   = randomBytes(32)
      const ed25519Sig = Buffer.from(ed25519.sign(wrongMsg, bundle.ed25519PrivKey))
      const mlDsaSig   = Buffer.from(ml_dsa65.sign(wrongMsg, bundle.mlDsaSecKey))
      body.device.last_resort_opk_pub       = lrOpkPub.toString('hex')
      body.device.last_resort_opk_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })
  })

  describe('username collision (timing-safe, oracle prevention)', () => {
    it('returns 409 when username is already taken', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [{ 1: 1 }] })
      const res = await post(validBody())
      assert.strictEqual(res.status, 409)
      assert.strictEqual(res.body.error, 'Registration failed')
    })

    it('still calls argon2.hash even when username is taken (timing-safe)', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [{ 1: 1 }] })
      await post(validBody())
      assert.strictEqual(argon2HashSpy.mock.calls.length, 1)
    })

    it('returns 409 on DB unique constraint violation (code 23505)', async () => {
      const innerErr = Object.assign(new Error('duplicate key'), { code: '23505' })
      globalThis.__db.clientQueryResults = [{ throwError: innerErr }]
      const res = await post(validBody())
      assert.strictEqual(res.status, 409)
      assert.strictEqual(res.body.error, 'Registration failed')
    })

    it('username-taken and DB-constraint-violation return identical JSON bodies (no enumeration)', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [{ 1: 1 }] })
      const res1 = await post(validBody())

      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const innerErr = Object.assign(new Error('duplicate key'), { code: '23505' })
      globalThis.__db.clientQueryResults = [{ throwError: innerErr }]
      const res2 = await post(validBody())

      assert.deepStrictEqual(res1.body, res2.body)
    })

    it('does not expose whether the username exists in the error message', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [{ 1: 1 }] })
      const res = await post(validBody())
      assert.doesNotMatch(res.body.error, /username/i)
      assert.doesNotMatch(res.body.error, /taken/i)
      assert.doesNotMatch(res.body.error, /exist/i)
    })
  })

  describe('DB error propagation', () => {
    it('returns 500 on unexpected DB error (not rethrown as 409)', async () => {
      globalThis.__db.clientQueryResults = [{ throwError: new Error('connection refused') }]
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })
  })
})
