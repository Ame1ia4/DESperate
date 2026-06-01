import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import express from 'express'
import { createSRPClient, createSRPServer } from 'js-srp6a'
import { authVerify } from '../../middleware/auth_verify.js'
import { getSessionKey, revokeSessionKey } from '../../state/session_keys.js'
import {
  SRP_EPHEMERAL_HEX,
  SRP_SESSION_PROOF_HEX,
} from '../../constants/auth.js'

// ── SRP fixture ──────────────────────────────────────────────────────────────

const USERNAME  = 'testuser'
const PASSWORD  = 'correct-horse-battery-staple'
const DEVICE_ID = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb'

const srpClient = createSRPClient('SHA-256', 3072)
const srpServer = createSRPServer('SHA-256', 3072)

const salt       = srpClient.generateSalt()
const privateKey = await srpClient.derivePrivateKey(salt, USERNAME, PASSWORD)
const verifier   = srpClient.deriveVerifier(privateKey)

const serverEphemeral = await srpServer.generateEphemeral(verifier)
const clientEphemeral = srpClient.generateEphemeral()
const clientSession   = await srpClient.deriveSession(
  clientEphemeral.secret,
  serverEphemeral.public,
  salt,
  USERNAME,
  privateKey
)

// ── DB mock helpers ───────────────────────────────────────────────────────────

function seqQueryImpl(...responses) {
  const queue = [...responses]
  return async (_sql) => {
    if (!queue.length) throw new Error('Unexpected extra query call')
    return queue.shift()
  }
}

// Shape from the device+user JOIN in auth_verify
const knownCreds      = () => ({ srp_salt: salt, srp_verifier: verifier })
const activeChallenge = () => ({ srp_server_secret: serverEphemeral.secret })

// ── App ───────────────────────────────────────────────────────────────────────

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/login', authVerify)
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

// Default: valid device+user, challenge consumed atomically
// Query order: [1] device+user JOIN, [2] DELETE FROM srp_challenges ... RETURNING,
//              [3] INSERT INTO device_sessions (storeSessionKey persistence)
beforeEach(() => {
  globalThis.__db.queryImpl = seqQueryImpl(
    { rows: [knownCreds()] },      // SELECT device+user JOIN
    { rows: [activeChallenge()] }, // DELETE FROM srp_challenges ... RETURNING
    { rows: [] },                  // INSERT INTO device_sessions (storeSessionKey)
  )
})

async function post(body) {
  const res = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

const validBody = () => ({
  username:              USERNAME,
  device_id:             DEVICE_ID,
  clientPublicEphemeral: clientEphemeral.public,
  clientSessionProof:    clientSession.proof,
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('POST /auth/login', () => {

  describe('happy path', () => {
    it('returns 200 with serverSessionProof', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.status, 200)
      assert.ok('serverSessionProof' in res.body)
    })

    it('serverSessionProof is a 64-char hex string (SHA-256)', async () => {
      const res = await post(validBody())
      assert.strictEqual(res.body.serverSessionProof.length, SRP_SESSION_PROOF_HEX)
      assert.match(res.body.serverSessionProof, /^[0-9a-f]+$/i)
    })

    it('serverSessionProof passes client-side SRP verification (mutual auth)', async () => {
      const res = await post(validBody())
      await assert.doesNotReject(() =>
        srpClient.verifySession(
          clientEphemeral.public,
          clientSession,
          res.body.serverSessionProof
        )
      )
    })

    it('includes session_token in the response', async () => {
      const res = await post(validBody())
      assert.ok('session_token' in res.body, 'session_token must be present for the client to authenticate')
      assert.match(res.body.session_token, /^[0-9a-f]{64}$/, 'session_token must be a 64-char hex string (HKDF-SHA256)')
    })

    it('does not echo back any credential fields', async () => {
      const res = await post(validBody())
      assert.ok(!('clientPublicEphemeral' in res.body))
      assert.ok(!('clientSessionProof'    in res.body))
      assert.ok(!('srp_verifier'          in res.body))
    })

    it('stores session key K in the session key store after successful handshake', async () => {
      await post(validBody())
      const K = await getSessionKey(DEVICE_ID)
      assert.ok(K !== null)
      assert.match(K, /^[0-9a-f]+$/i)
    })
  })

  describe('challenge lifecycle', () => {
    it('challenge is consumed atomically (DELETE RETURNING) on successful verification', async () => {
      const queries = []
      globalThis.__db.queryImpl = async (sql) => {
        queries.push(sql)
        if (sql.includes('srp_verifier'))      return { rows: [knownCreds()] }
        if (sql.includes('srp_challenges'))    return { rows: [activeChallenge()] }
        return { rows: [] }
      }
      await post(validBody())
      assert.ok(queries.some(q => q.includes('DELETE') && q.includes('srp_challenges')))
    })

    it('challenge is consumed even when M1 is wrong — K is NOT stored', async () => {
      // Flexible queryImpl handles all query types including device_sessions
      let queries = []
      globalThis.__db.queryImpl = async (sql) => {
        queries.push(sql)
        if (sql.includes('srp_verifier'))      return { rows: [knownCreds()] }
        if (sql.includes('srp_challenges'))    return { rows: [activeChallenge()] }
        return { rows: [] }
      }
      // Keys persist in the new model — revoke explicitly so this test starts clean
      await revokeSessionKey(DEVICE_ID)
      queries = [] // reset tracking; revokeSessionKey's DELETE is not part of this test

      const wrongM1 = randomBytes(SRP_SESSION_PROOF_HEX / 2).toString('hex')
      await post({ ...validBody(), clientSessionProof: wrongM1 })
      assert.ok(queries.some(q => q.includes('DELETE') && q.includes('srp_challenges')))
      assert.strictEqual(await getSessionKey(DEVICE_ID), null)
    })
  })

  describe('authentication failures — all return 401', () => {
    it('returns 401 when device/user credentials not found', async () => {
      globalThis.__db.queryImpl = seqQueryImpl({ rows: [] })
      const res = await post(validBody())
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when no challenge exists (init not called, or expired)', async () => {
      globalThis.__db.queryImpl = seqQueryImpl(
        { rows: [knownCreds()] },
        { rows: [] },
      )
      const res = await post(validBody())
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 for wrong M1 (incorrect password)', async () => {
      const wrongM1 = randomBytes(SRP_SESSION_PROOF_HEX / 2).toString('hex')
      const res = await post({ ...validBody(), clientSessionProof: wrongM1 })
      assert.strictEqual(res.status, 401)
    })

    it('all 401 responses have the same body shape (no info leak)', async () => {
      globalThis.__db.queryImpl = seqQueryImpl({ rows: [] })
      const unknownRes = await post(validBody())

      globalThis.__db.queryImpl = seqQueryImpl({ rows: [knownCreds()] }, { rows: [] })
      const noChallengeRes = await post(validBody())

      const wrongM1 = randomBytes(SRP_SESSION_PROOF_HEX / 2).toString('hex')
      globalThis.__db.queryImpl = seqQueryImpl(
        { rows: [knownCreds()] },
        { rows: [activeChallenge()] },
      )
      const wrongProofRes = await post({ ...validBody(), clientSessionProof: wrongM1 })

      assert.strictEqual(unknownRes.status, 401)
      assert.strictEqual(noChallengeRes.status, 401)
      assert.strictEqual(wrongProofRes.status, 401)
      assert.deepStrictEqual(unknownRes.body, noChallengeRes.body)
      assert.deepStrictEqual(noChallengeRes.body, wrongProofRes.body)
    })
  })

  describe('input validation — 400', () => {
    it('rejects missing username', async () => {
      const { username: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects missing device_id', async () => {
      const { device_id: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects invalid UUID device_id', async () => {
      assert.strictEqual((await post({ ...validBody(), device_id: 'not-a-uuid' })).status, 400)
    })

    it('rejects missing clientPublicEphemeral', async () => {
      const { clientPublicEphemeral: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects missing clientSessionProof', async () => {
      const { clientSessionProof: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects empty clientPublicEphemeral', async () => {
      assert.strictEqual(
        (await post({ ...validBody(), clientPublicEphemeral: '' })).status,
        400
      )
    })

    it('rejects clientPublicEphemeral above maximum length', async () => {
      assert.strictEqual(
        (await post({ ...validBody(), clientPublicEphemeral: 'a'.repeat(SRP_EPHEMERAL_HEX + 1) })).status,
        400
      )
    })

    it('rejects non-hex clientPublicEphemeral', async () => {
      assert.strictEqual(
        (await post({ ...validBody(), clientPublicEphemeral: 'z'.repeat(SRP_EPHEMERAL_HEX) })).status,
        400
      )
    })

    it('rejects clientSessionProof that is not exactly SRP_SESSION_PROOF_HEX chars', async () => {
      assert.strictEqual(
        (await post({ ...validBody(), clientSessionProof: 'a'.repeat(SRP_SESSION_PROOF_HEX - 1) })).status,
        400
      )
    })

    it('rejects non-hex clientSessionProof', async () => {
      assert.strictEqual(
        (await post({ ...validBody(), clientSessionProof: 'z'.repeat(SRP_SESSION_PROOF_HEX) })).status,
        400
      )
    })
  })

  describe('DB error handling', () => {
    it('returns 500 when the credential lookup throws', async () => {
      globalThis.__db.queryImpl = async () => { throw new Error('connection lost') }
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })

    it('returns 500 when the challenge DELETE RETURNING throws', async () => {
      globalThis.__db.queryImpl = async (sql) => {
        if (sql.includes('srp_verifier')) return { rows: [knownCreds()] }
        throw new Error('disk full')  // DELETE RETURNING throws
      }
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })
  })
})
