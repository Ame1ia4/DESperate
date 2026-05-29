import * as srp from 'secure-remote-password/server.js'
import { query } from '../database/db.js'
import {
  HEX_RE,
  USERNAME_MIN,
  USERNAME_MAX,
  USERNAME_REGEX,
  SRP_EPHEMERAL_HEX,
  SRP_EPHEMERAL_HEX_MIN,
  SRP_SESSION_PROOF_HEX,
} from '../constants/auth.js'

export async function authVerify(req, res) {
  const { username, clientPublicEphemeral, clientSessionProof } = req.body

  if (
    typeof username !== 'string' ||
    typeof clientPublicEphemeral !== 'string' ||
    typeof clientSessionProof !== 'string' ||
    username.length < USERNAME_MIN ||
    username.length > USERNAME_MAX ||
    !USERNAME_REGEX.test(username) ||
    clientPublicEphemeral.length < SRP_EPHEMERAL_HEX_MIN ||
    clientPublicEphemeral.length > SRP_EPHEMERAL_HEX ||
    !HEX_RE.test(clientPublicEphemeral) ||
    clientSessionProof.length !== SRP_SESSION_PROOF_HEX ||
    !HEX_RE.test(clientSessionProof)
  ) {
    return res.status(400).json({ error: 'Invalid request' })
  }

  const userResult = await query(
    'SELECT id, srp_salt, srp_verifier FROM users WHERE username = $1',
    [username]
  )
  const user = userResult.rows[0]

  if (!user) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  const challengeResult = await query(
    'SELECT srp_server_secret FROM srp_challenges WHERE user_id = $1 AND expires_at > NOW()',
    [user.id]
  )
  const challenge = challengeResult.rows[0]

  if (!challenge) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  // Consume the challenge before verifying — one-use regardless of outcome,
  // so a wrong password forces the client back to /auth/init rather than
  // allowing repeated guesses against the same server ephemeral.
  await query('DELETE FROM srp_challenges WHERE user_id = $1', [user.id])

  let serverSession
  try {
    serverSession = srp.deriveSession(
      challenge.srp_server_secret,
      clientPublicEphemeral,
      user.srp_salt,
      username,
      user.srp_verifier,
      clientSessionProof
    )
  } catch {
    // deriveSession throws for A mod N = 0 or M1 mismatch — both are auth failures.
    return res.status(401).json({ error: 'Authentication failed' })
  }

  console.info('auth_verify: session established', { username })
  res.json({ serverSessionProof: serverSession.proof })
}
