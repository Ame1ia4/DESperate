import { describe, it, before, after, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import { randomBytes } from 'node:crypto'
import srpClient from 'secure-remote-password/client.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { generateKeyBundle, validDeviceBody, zeroHex, randomHex } from '../helpers/keyFixtures.js'
import { issueNonce } from '../../handlers/auth/nonce.js'
import {
  X25519_PUB_BYTES, SIGNING_PUB_BYTES, DUAL_SIG_BYTES,
  MLKEM_PUB_BYTES, ED25519_SIG_BYTES,
  SRP_SALT_HEX, SRP_VERIFIER_HEX,
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

const testSalt     = srpClient.generateSalt()
const testVerifier = srpClient.deriveVerifier(
  srpClient.derivePrivateKey(testSalt, 'testuser', 'securePassword123')
)

before(() => new Promise(resolve => {
  bundle = generateKeyBundle()
  server = createApp().listen(0, () => {
    baseUrl = `http://localhost:${server.address().port}`
    resolve()
  })
}))

after(() => new Promise(resolve => server.close(resolve)))

const happyClientResults = () => [
  { rows: [{ id: 'user-uuid' }] },
  { rows: [{ id: 'device-uuid' }] },
]

beforeEach(() => {
  mock.restoreAll()
  globalThis.__db.queryImpl          = async () => ({ rows: [] }) // username not taken
  globalThis.__db.clientQueryResults = happyClientResults()
})

// Signs a hex nonce with the bundle's Ed25519 + ML-DSA keys.
function signNonce(nonce) {
  const nonceBytes = Buffer.from(nonce, 'hex')
  const ed25519Sig = Buffer.from(ed25519.sign(nonceBytes, bundle.ed25519PrivKey))
  const mlDsaSig   = Buffer.from(ml_dsa65.sign(nonceBytes, bundle.mlDsaSecKey))
  return Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
}

async function post(body) {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

// Generates a fresh bundle body each call — nonces are single-use so each
// test that succeeds or is expected to reach nonce-check must get a new one.
const validBody = () => {
  const nonce = issueNonce()
  return {
    username: 'testuser',
    bundle: {
      srp_salt:        testSalt,
      srp_verifier:    testVerifier,
      nonce,
      nonce_signature: signNonce(nonce),
      ...validDeviceBody(bundle),
    },
  }
}

describe('POST /auth/register', () => {
  describe('happy path', () => {
    it('returns 201 with deviceId for a valid registration', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.status, 201)
      assert.strictEqual(res.body.deviceId, 'device-uuid')
    })

    it('accepts registration without optional idk_pq_pub', async () => {
      const body = validBody()
      delete body.bundle.idk_pq_pub
      const res = await post(body)
      assert.strictEqual(res.status, 201)
    })

    it('accepts a device_name within length limit', async () => {
      const body = validBody()
      body.bundle.device_name = 'My Device'
      const res = await post(body)
      assert.strictEqual(res.status, 201)
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

  describe('bundle validation', () => {
    it('rejects missing bundle', async () => {
      const { bundle: _, ...body } = validBody()
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid bundle')
    })

    it('rejects bundle = null', async () => {
      const res = await post({ ...validBody(), bundle: null })
      assert.strictEqual(res.status, 400)
    })

    it('rejects bundle = array', async () => {
      const res = await post({ ...validBody(), bundle: [] })
      assert.strictEqual(res.status, 400)
    })

    it('rejects bundle = string', async () => {
      const res = await post({ ...validBody(), bundle: 'bad' })
      assert.strictEqual(res.status, 400)
    })

    it('rejects device_name longer than 100 chars', async () => {
      const body = validBody()
      body.bundle.device_name = 'x'.repeat(101)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid device_name')
    })

    it('accepts device_name = null (treated as absent)', async () => {
      const body = validBody()
      body.bundle.device_name = null
      const res = await post(body)
      assert.strictEqual(res.status, 201)
    })
  })

  describe('SRP credential validation', () => {
    it('rejects missing srp_salt', async () => {
      const body = validBody()
      delete body.bundle.srp_salt
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid srp_salt')
    })

    it('rejects srp_salt that is too short', async () => {
      const body = validBody()
      body.bundle.srp_salt = 'a'.repeat(SRP_SALT_HEX - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects srp_salt that is too long', async () => {
      const body = validBody()
      body.bundle.srp_salt = 'a'.repeat(SRP_SALT_HEX + 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects srp_salt with non-hex characters', async () => {
      const body = validBody()
      body.bundle.srp_salt = 'g'.repeat(SRP_SALT_HEX)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects missing srp_verifier', async () => {
      const body = validBody()
      delete body.bundle.srp_verifier
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid srp_verifier')
    })

    it('rejects srp_verifier that is too short', async () => {
      const body = validBody()
      body.bundle.srp_verifier = 'a'.repeat(SRP_VERIFIER_HEX - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects srp_verifier with non-hex characters', async () => {
      const body = validBody()
      body.bundle.srp_verifier = 'z'.repeat(SRP_VERIFIER_HEX)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })
  })

  describe('nonce validation (key-possession proof, Sesame §6.3)', () => {
    it('rejects missing nonce', async () => {
      const body = validBody()
      delete body.bundle.nonce
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid nonce')
    })

    it('rejects a nonce that was never issued', async () => {
      const body = validBody()
      body.bundle.nonce = randomHex(32)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid nonce')
    })

    it('rejects a nonce that has already been consumed (single-use)', async () => {
      const body = validBody()
      // First request consumes the nonce
      await post(body)
      // Second request with same nonce must fail
      globalThis.__db.queryImpl          = async () => ({ rows: [] })
      globalThis.__db.clientQueryResults = happyClientResults()
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid nonce')
    })

    it('rejects missing nonce_signature', async () => {
      const body = validBody()
      delete body.bundle.nonce_signature
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects nonce_signature of all zeros (valid length, invalid sig)', async () => {
      const body = validBody()
      body.bundle.nonce_signature = zeroHex(DUAL_SIG_BYTES)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects nonce_signature signed with a different keypair', async () => {
      const body    = validBody()
      const otherPk = randomBytes(32)
      const { secretKey: otherMlSec } = ml_dsa65.keygen(randomBytes(32))
      const nonceBytes  = Buffer.from(body.bundle.nonce, 'hex')
      const badEd = Buffer.from(ed25519.sign(nonceBytes, otherPk))
      const badMl = Buffer.from(ml_dsa65.sign(nonceBytes, otherMlSec))
      body.bundle.nonce_signature = Buffer.concat([badEd, badMl]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })
  })

  describe('key material size attacks', () => {
    it('rejects idk_classical_pub that is one byte short', async () => {
      const body = validBody()
      body.bundle.idk_classical_pub = randomHex(X25519_PUB_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.match(res.body.error, /idk_classical_pub/)
    })

    it('rejects idk_classical_pub with non-hex chars', async () => {
      const body = validBody()
      body.bundle.idk_classical_pub = 'z'.repeat(X25519_PUB_BYTES * 2)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects identity_signing_pub with wrong total length', async () => {
      const body = validBody()
      body.bundle.identity_signing_pub = randomHex(SIGNING_PUB_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.match(res.body.error, /identity_signing_pub/)
    })

    it('rejects signed_prekey_pub with wrong length', async () => {
      const body = validBody()
      body.bundle.signed_prekey_pub = randomHex(X25519_PUB_BYTES + 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects signed_prekey_signature with wrong length', async () => {
      const body = validBody()
      body.bundle.signed_prekey_signature = randomHex(DUAL_SIG_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('rejects idk_pq_pub with wrong length when provided', async () => {
      const body = validBody()
      body.bundle.idk_pq_pub = randomHex(MLKEM_PUB_BYTES - 1)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.match(res.body.error, /idk_pq_pub/)
    })
  })

  describe('signed prekey signature verification', () => {
    it('rejects signed_prekey_signature of all zeros (valid length, invalid sig)', async () => {
      const body = validBody()
      body.bundle.signed_prekey_signature = zeroHex(DUAL_SIG_BYTES)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects signed_prekey_signature of random bytes', async () => {
      const body = validBody()
      body.bundle.signed_prekey_signature = randomHex(DUAL_SIG_BYTES)
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects sig signed over a different message (not the SPK pub)', async () => {
      const body       = validBody()
      const wrongMsg   = randomBytes(32)
      const ed25519Sig = Buffer.from(ed25519.sign(wrongMsg, bundle.ed25519PrivKey))
      const mlDsaSig   = Buffer.from(ml_dsa65.sign(wrongMsg, bundle.mlDsaSecKey))
      body.bundle.signed_prekey_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects sig signed with a different (unrelated) keypair', async () => {
      const body                      = validBody()
      const otherPriv                 = randomBytes(32)
      const { secretKey: otherMlSec } = ml_dsa65.keygen(randomBytes(32))
      const spkPub                    = Buffer.from(body.bundle.signed_prekey_pub, 'hex')
      const ed25519Sig                = Buffer.from(ed25519.sign(spkPub, otherPriv))
      const mlDsaSig                  = Buffer.from(ml_dsa65.sign(spkPub, otherMlSec))
      body.bundle.signed_prekey_signature = Buffer.concat([ed25519Sig, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects when only the ML-DSA half is valid (ed25519 is zeros)', async () => {
      const body     = validBody()
      const spkPub   = Buffer.from(body.bundle.signed_prekey_pub, 'hex')
      const zeroEd   = Buffer.alloc(ED25519_SIG_BYTES)
      const mlDsaSig = Buffer.from(ml_dsa65.sign(spkPub, bundle.mlDsaSecKey))
      body.bundle.signed_prekey_signature = Buffer.concat([zeroEd, mlDsaSig]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })

    it('rejects when only the Ed25519 half is valid (ml_dsa is zeros)', async () => {
      const body       = validBody()
      const spkPub     = Buffer.from(body.bundle.signed_prekey_pub, 'hex')
      const ed25519Sig = Buffer.from(ed25519.sign(spkPub, bundle.ed25519PrivKey))
      const zeroMl     = Buffer.alloc(DUAL_SIG_BYTES - ED25519_SIG_BYTES)
      body.bundle.signed_prekey_signature = Buffer.concat([ed25519Sig, zeroMl]).toString('hex')
      const res = await post(body)
      assert.strictEqual(res.status, 400)
      assert.strictEqual(res.body.error, 'Invalid key bundle')
    })
  })

  describe('username collision (oracle prevention)', () => {
    it('returns 409 when username is already taken', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: [{ 1: 1 }] })
      const res = await post(validBody())
      assert.strictEqual(res.status, 409)
      assert.strictEqual(res.body.error, 'Registration failed')
    })

    it('returns 409 on DB unique constraint violation (code 23505)', async () => {
      const innerErr = Object.assign(new Error('duplicate key'), { code: '23505' })
      globalThis.__db.clientQueryResults = [{ throwError: innerErr }]
      const res = await post(validBody())
      assert.strictEqual(res.status, 409)
      assert.strictEqual(res.body.error, 'Registration failed')
    })

    it('username-taken and DB-constraint-violation return identical JSON bodies', async () => {
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
    it('returns 500 on unexpected DB error', async () => {
      globalThis.__db.clientQueryResults = [{ throwError: new Error('connection refused') }]
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })
  })
})
