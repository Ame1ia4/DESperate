import * as srp from 'secure-remote-password/server.js'
import { createHmac, hkdfSync } from 'node:crypto'
import { query, withTransaction } from '../database/db.js'
import { isValidUsername, isValidUUID, isValidClientPublicEphemeral } from '../utils/validate.js'
import { SRP_VERIFIER_HEX } from '../constants/auth.js'

// Fail fast at startup — a missing secret makes fakeSalt() throw only for
// unknown users, turning the unknown-user path into a 500 (enumeration oracle).
if (!process.env.AUTH_FAKE_SECRET) {
  throw new Error('AUTH_FAKE_SECRET environment variable is required')
}
const SERVER_SECRET = process.env.AUTH_FAKE_SECRET

// Both are keyed to AUTH_FAKE_SECRET so an external attacker cannot pre-compute
// the mapping even if they observe many responses for the same username.
// RFC 5054 §2.5.1.3

function fakeSalt(username) {
  return createHmac('sha256', SERVER_SECRET).update(username).digest('hex')
}

function fakeVerifier(username) {
  // HKDF-SHA256 expands the HMAC key to the full 256 bytes required for a
  // 2048-bit SRP verifier (RFC 5054 Appendix A §3).
  const okm = hkdfSync('sha256', SERVER_SECRET, username, 'srp-fake-verifier', SRP_VERIFIER_HEX / 2)
  return Buffer.from(okm).toString('hex')
}

export async function authInit(req, res) {
  const { username, device_id, clientPublicEphemeral } = req.body

  if (
    !isValidUsername(username) ||
    !isValidUUID(device_id) ||
    !isValidClientPublicEphemeral(clientPublicEphemeral)
  ) {
    return res.status(400).json({ error: 'Invalid request' })
  }

  // Single JOIN: verifies username, device ownership, and revocation status together.
  // A missing row covers unknown user, device not belonging to user, and revoked device —
  // all three fall through to the fake path (RFC 5054 §2.5.1.3 enumeration prevention).
  const result = await query(
    `SELECT u.id AS user_id, u.srp_salt, u.srp_verifier, d.id AS device_id
     FROM   users u
     JOIN   devices d ON d.user_id = u.id
                    AND d.id       = $2
                    AND d.revoked  = FALSE
     WHERE  u.username = $1`,
    [username, device_id]
  )
  const row = result.rows[0]

  if (!row) {
    // RFC 5054 §2.5.1.3 — return fake salt + ephemeral so the response is
    // indistinguishable from a valid one. Round 2 will reject via proof mismatch.
    const ephemeral = srp.generateEphemeral(fakeVerifier(username))
    // Equalise timing with real path — real path runs a DELETE+INSERT transaction;
    // fake path runs a no-op DELETE so both paths pay similar DB round-trip cost.
    await withTransaction(async (client) => {
      await client.query(
        'DELETE FROM srp_challenges WHERE device_id = $1',
        ['00000000-0000-0000-0000-000000000000']
      )
    })
    console.info('auth_init: challenge issued (fake)', { username })
    return res.json({ salt: fakeSalt(username), serverPublicEphemeral: ephemeral.public })
  }

  // RFC 5054 §2.5.3: b SHOULD be ≥ 256 bits (enforced by the library).
  const serverEphemeral = srp.generateEphemeral(row.srp_verifier)

  // Atomically replace any existing challenge — prevents accumulation and
  // ensures a retrying client always starts a fresh handshake.
  await withTransaction(async (client) => {
    await client.query(
      'DELETE FROM srp_challenges WHERE device_id = $1',
      [row.device_id]
    )
    // Store only b (serverEphemeral.secret) — B is sent to the client and
    // discarded; A is re-sent by the client in round 2 (RFC 5054 §2.5.3).
    await client.query(
      'INSERT INTO srp_challenges (device_id, srp_server_secret) VALUES ($1, $2)',
      [row.device_id, serverEphemeral.secret]
    )
  })

  console.info('auth_init: challenge issued', { username, device_id })
  res.json({
    salt: row.srp_salt,
    serverPublicEphemeral: serverEphemeral.public,
  })
}
