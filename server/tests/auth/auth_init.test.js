import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import express from 'express'
import { authInit } from '../../middleware/auth_init.js'
import {
  USERNAME_MIN,
  USERNAME_MAX,
  SRP_SALT_HEX,
  SRP_EPHEMERAL_HEX,
} from '../../constants/auth.js'

// ── Helpers ──────────────────────────────────────────────────────────────────

const validEphemeral = () => randomBytes(SRP_EPHEMERAL_HEX / 2).toString('hex')

const FAKE_DB_SALT     = 'b'.repeat(SRP_SALT_HEX)
const FAKE_DB_VERIFIER = 'a'.repeat(768)
const VALID_DEVICE_ID  = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'

// Shape returned by the JOIN query in auth_init
const knownRow = () => ({
  user_id:      'user-uuid',
  srp_salt:     FAKE_DB_SALT,
  srp_verifier: FAKE_DB_VERIFIER,
  device_id:    VALID_DEVICE_ID,
})

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/init', authInit)
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

// Default: known user+device, transaction succeeds (DELETE + INSERT = 2 client queries)
beforeEach(() => {
  globalThis.__db.queryImpl          = async () => ({ rows: [knownRow()] })
  globalThis.__db.clientQueryResults = [{ rows: [] }, { rows: [] }]
})

async function post(body) {
  const res = await fetch(`${baseUrl}/auth/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

const validBody = () => ({
  username:             'testuser',
  device_id:            VALID_DEVICE_ID,
  clientPublicEphemeral: validEphemeral(),
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('POST /auth/init', () => {
  describe('happy path — known user + device', () => {
    it('returns 200 with salt and serverPublicEphemeral', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.status, 200)
      assert.ok('salt' in res.body)
      assert.ok('serverPublicEphemeral' in res.body)
    })

    it("returns the user's srp_salt from the database", async () => {
      const res = await post(validBody())
      assert.strictEqual(res.body.salt, FAKE_DB_SALT)
    })

    it('serverPublicEphemeral is a 768-char hex string (RFC 5054 Appendix A §3, 3072-bit group)', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.body.serverPublicEphemeral.length, SRP_EPHEMERAL_HEX)
      assert.match(res.body.serverPublicEphemeral, /^[0-9a-f]+$/i)
    })

    it('does not echo clientPublicEphemeral back in the response', async () => {
      const body = validBody()
      const res = await post(body)
      assert.ok(!('clientPublicEphemeral' in res.body))
    })

    it('uses a transaction — consumes both DELETE and INSERT client queries', async () => {
      // withTransaction issues DELETE then INSERT; if only 1 result is provided
      // the second query throws, causing a 500. Two results → 200 proves both run.
      globalThis.__db.clientQueryResults = [{ rows: [] }] // only 1 — missing INSERT result
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })
  })

  describe('unknown user / device — RFC 5054 §2.5.1.3', () => {
    // All three cases (unknown user, device not belonging to user, revoked device)
    // return the same fake response — no row from the JOIN covers all of them.
    beforeEach(() => {
      globalThis.__db.queryImpl          = async () => ({ rows: [] })
      globalThis.__db.clientQueryResults = [{ rows: [] }] // timing-equalisation DELETE
    })

    it('returns 200 (not 404) so callers cannot detect missing accounts or devices', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.status, 200)
    })

    it('response has the same shape as a known-user response', async () => {
      const res = await post(validBody())
      assert.ok('salt' in res.body)
      assert.ok('serverPublicEphemeral' in res.body)
    })

    it('fake salt is exactly SRP_SALT_HEX hex chars', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.body.salt.length, SRP_SALT_HEX)
      assert.match(res.body.salt, /^[0-9a-f]+$/i)
    })

    it('fake serverPublicEphemeral is exactly SRP_EPHEMERAL_HEX hex chars', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.body.serverPublicEphemeral.length, SRP_EPHEMERAL_HEX)
    })

    it('same username always produces the same fake salt (deterministic — prevents repeat-probe enumeration)', async () => {
      const body = validBody()
      const res1 = await post(body)
      const res2 = await post({ ...body, clientPublicEphemeral: validEphemeral() })
      assert.strictEqual(res1.body.salt, res2.body.salt)
    })

    it('different usernames produce different fake salts', async () => {
      const res1 = await post({ ...validBody(), username: 'alice' })
      const res2 = await post({ ...validBody(), username: 'bobby' })
      assert.notStrictEqual(res1.body.salt, res2.body.salt)
    })

    it('does not INSERT a challenge for unknown users/devices (timing DELETE only, no INSERT)', async () => {
      // Real path: DELETE + INSERT (2 client queries). Fake path: DELETE only (1 query).
      // Providing exactly 1 clientQueryResult proves no INSERT was attempted.
      globalThis.__db.clientQueryResults = [{ rows: [] }]
      const res = await post(validBody())
      assert.strictEqual(res.status, 200)
    })
  })

  describe('enumeration prevention', () => {
    it('known and unknown user/device return the same HTTP status', async () => {
      const res1 = await post(validBody())

      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res2 = await post(validBody())

      assert.strictEqual(res1.status, res2.status)
    })

    it('known and unknown user/device response bodies have identical keys', async () => {
      const res1 = await post(validBody())

      globalThis.__db.queryImpl = async () => ({ rows: [] })
      const res2 = await post(validBody())

      assert.deepStrictEqual(Object.keys(res1.body).sort(), Object.keys(res2.body).sort())
    })
  })

  describe('username validation', () => {
    const cases = [
      [undefined,                    'missing'],
      [null,                         'null'],
      [42,                           'number type'],
      ['ab',                         `too short (${USERNAME_MIN - 1} chars)`],
      ['a'.repeat(USERNAME_MAX + 1), `too long (${USERNAME_MAX + 1} chars)`],
      ["admin'--",                   'SQL injection attempt'],
      ['user name',                  'contains space'],
      ['user@domain',                'contains @'],
      ['ñaméé',                      'non-ASCII unicode'],
      ['',                           'empty string'],
    ]

    for (const [username, desc] of cases) {
      it(`rejects username: ${desc}`, async () => {
        const res = await post({ ...validBody(), username })
        assert.strictEqual(res.status, 400)
      })
    }

    it(`accepts username at minimum length (${USERNAME_MIN} chars)`, async () => {
      const res = await post({ ...validBody(), username: 'a'.repeat(USERNAME_MIN) })
      assert.strictEqual(res.status, 200)
    })

    it(`accepts username at maximum length (${USERNAME_MAX} chars)`, async () => {
      const res = await post({ ...validBody(), username: 'a'.repeat(USERNAME_MAX) })
      assert.strictEqual(res.status, 200)
    })
  })

  describe('device_id validation', () => {
    const invalidCases = [
      [undefined,               'missing'],
      [null,                    'null'],
      [42,                      'number'],
      ['',                      'empty string'],
      ['not-a-uuid',            'non-UUID string'],
      ['tooshort-uuid',         'wrong structure'],
    ]

    for (const [device_id, desc] of invalidCases) {
      it(`rejects device_id: ${desc}`, async () => {
        const res = await post({ ...validBody(), device_id })
        assert.strictEqual(res.status, 400)
      })
    }

    it('accepts a valid UUID v4', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.status, 200)
    })
  })

  describe('clientPublicEphemeral validation', () => {
    it('rejects missing clientPublicEphemeral', async () => {
      const { clientPublicEphemeral: _, ...body } = validBody()
      const res = await post(body)
      assert.strictEqual(res.status, 400)
    })

    it('accepts clientPublicEphemeral shorter than SRP_EPHEMERAL_HEX (leading-zero-stripped value)', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'a'.repeat(SRP_EPHEMERAL_HEX - 1) })
      assert.strictEqual(res.status, 200)
    })

    it('accepts a single hex char as clientPublicEphemeral (A mod N ≠ 0 is enforced by the library, not length)', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'a' })
      assert.strictEqual(res.status, 200)
    })

    it('rejects empty clientPublicEphemeral', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: '' })
      assert.strictEqual(res.status, 400)
    })

    it('rejects clientPublicEphemeral that is one char too long', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'a'.repeat(SRP_EPHEMERAL_HEX + 1) })
      assert.strictEqual(res.status, 400)
    })

    it('rejects non-string clientPublicEphemeral', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 12345 })
      assert.strictEqual(res.status, 400)
    })

    it('rejects clientPublicEphemeral with non-hex characters', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'z'.repeat(SRP_EPHEMERAL_HEX) })
      assert.strictEqual(res.status, 400)
    })
  })

  describe('DB error handling', () => {
    it('returns 500 on unexpected query error', async () => {
      globalThis.__db.queryImpl = async () => { throw new Error('connection refused') }
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })

    it('returns 500 when the challenge transaction fails', async () => {
      globalThis.__db.clientQueryResults = [{ throwError: new Error('disk full') }]
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })
  })
})
