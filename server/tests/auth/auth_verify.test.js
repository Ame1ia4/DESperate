import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import express from 'express'
import * as srpClient from 'secure-remote-password/client.js'
import * as srpServer from 'secure-remote-password/server.js'
import { authVerify } from '../../middleware/auth_verify.js'
import {
  SRP_EPHEMERAL_HEX,
  SRP_EPHEMERAL_HEX_MIN,
  SRP_SESSION_PROOF_HEX,
} from '../../constants/auth.js'

// ── SRP fixture ──────────────────────────────────────────────────────────────
// Real SRP values generated once per test run.
// Tests that need valid credentials pull from here; invalid-credential tests
// use this fixture's DB values but submit wrong A or M1.

const USERNAME = 'testuser'
const PASSWORD = 'correct-horse-battery-staple'

const salt       = srpClient.generateSalt()
const privateKey = srpClient.derivePrivateKey(salt, USERNAME, PASSWORD)
const verifier   = srpClient.deriveVerifier(privateKey)

// Server generates b and B from the verifier
const serverEphemeral = srpServer.generateEphemeral(verifier)

// Client generates a and A, then computes M1 knowing B
const clientEphemeral = srpClient.generateEphemeral()
const clientSession   = srpClient.deriveSession(
  clientEphemeral.secret,
  serverEphemeral.public,
  salt,
  USERNAME,
  privateKey
)

// ── DB mock helpers ───────────────────────────────────────────────────────────

// Returns a queryImpl that serves responses in order, one per call.
function seqQueryImpl(...responses) {
  const queue = [...responses]
  return async () => {
    if (!queue.length) throw new Error('Unexpected extra query call')
    return queue.shift()
  }
}

const knownUser      = () => ({ id: 'user-uuid', srp_salt: salt, srp_verifier: verifier })
const activeChallenge = () => ({ srp_server_secret: serverEphemeral.secret })

// ── App ───────────────────────────────────────────────────────────────────────

function createApp() {
  const app = express()
  app.use(express.json())
  app.post('/auth/verify', authVerify)
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

// Default: known user with a valid, unexpired challenge
beforeEach(() => {
  globalThis.__db.queryImpl = seqQueryImpl(
    { rows: [knownUser()] },       // SELECT users
    { rows: [activeChallenge()] }, // SELECT srp_challenges
    { rows: [] },                  // DELETE srp_challenges
  )
})

async function post(body) {
  const res = await fetch(`${baseUrl}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

const validBody = () => ({
  username: USERNAME,
  clientPublicEphemeral: clientEphemeral.public,
  clientSessionProof:    clientSession.proof,
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('POST /auth/verify', () => {

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

    it('serverSessionProof passes client-side SRP verification', async () => {
      const res = await post(validBody())
      // srpClient.verifySession throws if M2 is wrong
      assert.doesNotThrow(() =>
        srpClient.verifySession(
          clientEphemeral.public,
          clientSession,
          res.body.serverSessionProof
        )
      )
    })

    it('does not echo back any credential fields', async () => {
      const res = await post(validBody())
      assert.ok(!('clientPublicEphemeral' in res.body))
      assert.ok(!('clientSessionProof'    in res.body))
      assert.ok(!('srp_verifier'          in res.body))
    })
  })

  describe('challenge lifecycle', () => {
    it('challenge is deleted on successful verification', async () => {
      const queries = []
      globalThis.__db.queryImpl = async (sql) => {
        queries.push(sql)
        if (sql.includes('FROM users'))          return { rows: [knownUser()] }
        if (sql.includes('FROM srp_challenges')) return { rows: [activeChallenge()] }
        return { rows: [] }
      }
      await post(validBody())
      assert.ok(queries.some(q => q.includes('DELETE') && q.includes('srp_challenges')))
    })

    it('challenge is deleted even when M1 is wrong (prevents brute-force reuse)', async () => {
      const queries = []
      globalThis.__db.queryImpl = async (sql) => {
        queries.push(sql)
        if (sql.includes('FROM users'))          return { rows: [knownUser()] }
        if (sql.includes('FROM srp_challenges')) return { rows: [activeChallenge()] }
        return { rows: [] }
      }
      const wrongM1 = randomBytes(SRP_SESSION_PROOF_HEX / 2).toString('hex')
      await post({ ...validBody(), clientSessionProof: wrongM1 })
      assert.ok(queries.some(q => q.includes('DELETE') && q.includes('srp_challenges')))
    })
  })

  describe('authentication failures — all return 401', () => {
    it('returns 401 for unknown username', async () => {
      globalThis.__db.queryImpl = seqQueryImpl({ rows: [] })
      const res = await post(validBody())
      assert.strictEqual(res.status, 401)
    })

    it('returns 401 when no challenge exists (init not called, or expired)', async () => {
      globalThis.__db.queryImpl = seqQueryImpl(
        { rows: [knownUser()] },
        { rows: [] },             // no challenge row
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
      const unknownUserRes = await (async () => {
        globalThis.__db.queryImpl = seqQueryImpl({ rows: [] })
        return post(validBody())
      })()

      globalThis.__db.queryImpl = seqQueryImpl(
        { rows: [knownUser()] },
        { rows: [] },
      )
      const noChallengeRes = await post(validBody())

      const wrongM1 = randomBytes(SRP_SESSION_PROOF_HEX / 2).toString('hex')
      globalThis.__db.queryImpl = seqQueryImpl(
        { rows: [knownUser()] },
        { rows: [activeChallenge()] },
        { rows: [] },
      )
      const wrongProofRes = await post({ ...validBody(), clientSessionProof: wrongM1 })

      assert.strictEqual(unknownUserRes.status, 401)
      assert.strictEqual(noChallengeRes.status, 401)
      assert.strictEqual(wrongProofRes.status, 401)
      assert.deepStrictEqual(unknownUserRes.body, noChallengeRes.body)
      assert.deepStrictEqual(noChallengeRes.body, wrongProofRes.body)
    })
  })

  describe('input validation — 400', () => {
    it('rejects missing username', async () => {
      const { username: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects missing clientPublicEphemeral', async () => {
      const { clientPublicEphemeral: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects missing clientSessionProof', async () => {
      const { clientSessionProof: _, ...body } = validBody()
      assert.strictEqual((await post(body)).status, 400)
    })

    it('rejects clientPublicEphemeral below minimum length', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'a'.repeat(SRP_EPHEMERAL_HEX_MIN - 1) })
      assert.strictEqual(res.status, 400)
    })

    it('rejects clientPublicEphemeral above maximum length', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'a'.repeat(SRP_EPHEMERAL_HEX + 1) })
      assert.strictEqual(res.status, 400)
    })

    it('rejects non-hex clientPublicEphemeral', async () => {
      const res = await post({ ...validBody(), clientPublicEphemeral: 'z'.repeat(SRP_EPHEMERAL_HEX) })
      assert.strictEqual(res.status, 400)
    })

    it('rejects clientSessionProof that is not exactly SRP_SESSION_PROOF_HEX chars', async () => {
      const res = await post({ ...validBody(), clientSessionProof: 'a'.repeat(SRP_SESSION_PROOF_HEX - 1) })
      assert.strictEqual(res.status, 400)
    })

    it('rejects non-hex clientSessionProof', async () => {
      const res = await post({ ...validBody(), clientSessionProof: 'z'.repeat(SRP_SESSION_PROOF_HEX) })
      assert.strictEqual(res.status, 400)
    })
  })

  describe('DB error handling', () => {
    it('returns 500 when the user lookup throws', async () => {
      globalThis.__db.queryImpl = async () => { throw new Error('connection lost') }
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })

    it('returns 500 when the challenge DELETE throws', async () => {
      globalThis.__db.queryImpl = async (sql) => {
        if (sql.includes('FROM users'))          return { rows: [knownUser()] }
        if (sql.includes('FROM srp_challenges')) return { rows: [activeChallenge()] }
        throw new Error('disk full')
      }
      const res = await post(validBody())
      assert.strictEqual(res.status, 500)
    })
  })
})
