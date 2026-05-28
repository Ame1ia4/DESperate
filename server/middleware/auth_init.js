import * as srp from 'secure-remote-password/server'
import { createHmac, hkdfSync } from 'node:crypto'
import { query, withTransaction } from '../database/db.js'
import {
  USERNAME_MIN,
  USERNAME_MAX,
  USERNAME_REGEX,
  SRP_EPHEMERAL_HEX,
  SRP_VERIFIER_HEX,
} from '../constants/auth.js'

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
  const { username, clientPublicEphemeral } = req.body

  if (
    typeof username !== 'string' ||
    typeof clientPublicEphemeral !== 'string' ||
    username.length < USERNAME_MIN ||
    username.length > USERNAME_MAX ||
    !USERNAME_REGEX.test(username) ||
    clientPublicEphemeral.length !== SRP_EPHEMERAL_HEX
  ) {
    return res.status(400).json({ error: 'Invalid request' })
  }

  const result = await query(
    'SELECT id, srp_salt, srp_verifier FROM users WHERE username = $1',
    [username]
  )
  const user = result.rows[0]

  if (!user) {
    // RFC 5054 §2.5.1.3 — simulate with fake salt + verifier; round 2 will
    // reject with the equivalent of bad_record_mac (proof mismatch).
    const ephemeral = srp.generateEphemeral(fakeVerifier(username))
    console.info('auth_init: challenge issued', { username })
    return res.json({ salt: fakeSalt(username), serverPublicEphemeral: ephemeral.public })
  }

  // RFC 5054 §2.5.3: b SHOULD be ≥ 256 bits (enforced by the library).
  const serverEphemeral = srp.generateEphemeral(user.srp_verifier)

  // Atomically replace any existing challenge — prevents accumulation and
  // ensures a retrying client always starts a fresh handshake.
  await withTransaction(async (client) => {
    await client.query(
      'DELETE FROM srp_challenges WHERE user_id = $1',
      [user.id]
    )
    // Store only b (serverEphemeral.secret) — B is sent to the client and
    // discarded; A is re-sent by the client in round 2 (RFC 5054 §2.5.3).
    await client.query(
      'INSERT INTO srp_challenges (user_id, srp_server_secret) VALUES ($1, $2)',
      [user.id, serverEphemeral.secret]
    )
  })

  console.info('auth_init: challenge issued', { username })
  res.json({
    salt: user.srp_salt,
    serverPublicEphemeral: serverEphemeral.public,
  })
}
