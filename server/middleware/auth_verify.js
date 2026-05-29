import * as srp from 'secure-remote-password/server.js'
import { query } from '../database/db.js'
import {
  HEX_RE,
  UUID_RE,
  USERNAME_MIN,
  USERNAME_MAX,
  USERNAME_REGEX,
  SRP_EPHEMERAL_HEX,
  SRP_EPHEMERAL_HEX_MIN,
  SRP_SESSION_PROOF_HEX,
  SRP_SESSION_INTERVAL,
} from '../constants/auth.js'

export async function authVerify(req, res) {
  const { username, device_id, clientPublicEphemeral, clientSessionProof } = req.body

  if (
    typeof username !== 'string' ||
    typeof device_id !== 'string' ||
    typeof clientPublicEphemeral !== 'string' ||
    typeof clientSessionProof !== 'string' ||
    username.length < USERNAME_MIN ||
    username.length > USERNAME_MAX ||
    !USERNAME_REGEX.test(username) ||
    !UUID_RE.test(device_id) ||
    clientPublicEphemeral.length < SRP_EPHEMERAL_HEX_MIN ||
    clientPublicEphemeral.length > SRP_EPHEMERAL_HEX ||
    !HEX_RE.test(clientPublicEphemeral) ||
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

  const challengeResult = await query(
    'SELECT srp_server_secret FROM srp_challenges WHERE device_id = $1 AND expires_at > NOW()',
    [device_id]
  )
  const challenge = challengeResult.rows[0]

  if (!challenge) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  // Consume the challenge before verifying — one-use regardless of outcome,
  // so a wrong password forces the client back to /auth/init rather than
  // allowing repeated guesses against the same server ephemeral.
  await query('DELETE FROM srp_challenges WHERE device_id = $1', [device_id])

  let serverSession
  try {
    serverSession = srp.deriveSession(
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

  // Stamp session lifetime on the device row so requireAuth can gate subsequent requests.
  await query(
    `UPDATE devices
     SET srp_verified_at = NOW(),
         srp_expires_at  = NOW() + INTERVAL '${SRP_SESSION_INTERVAL}'
     WHERE id = $1`,
    [device_id]
  )

  console.info('auth_login: session established', { username, device_id })
  res.json({ serverSessionProof: serverSession.proof })
}
