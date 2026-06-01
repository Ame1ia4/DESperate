import { hkdfSync } from 'node:crypto'
import { createSRPServer } from 'js-srp6a'
import { query } from '../database/db.js'
import { storeSessionKey } from '../state/session_keys.js'
import { isValidUsername, isValidUUID, isValidClientPublicEphemeral } from '../utils/validate.js'
import { HEX_RE, SRP_SESSION_PROOF_HEX } from '../constants/auth.js'

const srp = createSRPServer('SHA-256', 3072)

export async function authVerify(req, res) {
  const { username, device_id, clientPublicEphemeral, clientSessionProof } = req.body

  if (
    !isValidUsername(username) ||
    !isValidUUID(device_id) ||
    !isValidClientPublicEphemeral(clientPublicEphemeral) ||
    typeof clientSessionProof !== 'string' ||
    clientSessionProof.length !== SRP_SESSION_PROOF_HEX ||
    !HEX_RE.test(clientSessionProof)
  ) {
    return res.status(400).json({ error: 'Invalid request' })
  }

  // Load credentials — verifies device belongs to username and is not revoked.
  const credResult = await query(
    `SELECT u.srp_salt, u.srp_verifier
     FROM   devices d
     JOIN   users u ON u.id = d.user_id
     WHERE  d.id       = $1
       AND  d.revoked  = FALSE
       AND  u.username = $2`,
    [device_id, username]
  )
  const creds = credResult.rows[0]

  if (!creds) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  // Atomic delete-and-read — single round trip, no race window between
  // SELECT and DELETE where two concurrent requests could both read the challenge.
  const challengeResult = await query(
    'DELETE FROM srp_challenges WHERE device_id = $1 AND expires_at > NOW() RETURNING srp_server_secret',
    [device_id]
  )
  const challenge = challengeResult.rows[0]

  if (!challenge) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  let serverSession
  try {
    serverSession = await srp.deriveSession(
      challenge.srp_server_secret,
      clientPublicEphemeral,
      creds.srp_salt,
      username,
      creds.srp_verifier,
      clientSessionProof
    )
  } catch {
    // deriveSession throws for A mod N = 0 or M1 mismatch — both are auth failures.
    return res.status(401).json({ error: 'Authentication failed' })
  }

  // Derive session token from K via HKDF — K itself is never stored or transmitted.
  const sessionTokenBuf = hkdfSync(
    'sha256',
    Buffer.from(serverSession.key, 'hex'),
    Buffer.alloc(0),
    'session-token',
    32
  )
  const session_token = Buffer.from(sessionTokenBuf).toString('hex')
  await storeSessionKey(device_id, session_token)

  console.info('auth_login: session established', { username, device_id })
  res.json({ serverSessionProof: serverSession.proof, session_token })
}
