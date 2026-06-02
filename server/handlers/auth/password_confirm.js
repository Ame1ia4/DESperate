import { srp } from '../../lib/srp.js'
import { query } from '../../database/db.js'
import { revokeSessionKey } from '../../state/session_keys.js'
import { isValidClientPublicEphemeral } from '../../utils/validate.js'
import {
  HEX_RE,
  SRP_SALT_HEX,
  SRP_VERIFIER_HEX,
  SRP_SESSION_PROOF_HEX,
} from '../../constants/auth.js'

// Round 2 of the password-change flow.
// Verifies the client knows the old password (via SRP M1), then atomically
// replaces the SRP credentials and revokes ALL sessions for the user so every
// device must re-authenticate with the new password.
export async function passwordChangeConfirm(req, res) {
  const { clientPublicEphemeral, clientSessionProof, new_salt, new_verifier } = req.body

  if (
    !isValidClientPublicEphemeral(clientPublicEphemeral) ||
    typeof clientSessionProof !== 'string' ||
    clientSessionProof.length !== SRP_SESSION_PROOF_HEX ||
    !HEX_RE.test(clientSessionProof) ||
    typeof new_salt !== 'string' ||
    new_salt.length !== SRP_SALT_HEX ||
    !HEX_RE.test(new_salt) ||
    typeof new_verifier !== 'string' ||
    new_verifier.length < 1 ||
    new_verifier.length > SRP_VERIFIER_HEX ||
    !HEX_RE.test(new_verifier)
  ) {
    return res.status(400).json({ error: 'Invalid request' })
  }

  // Fetch credentials and consume the challenge in parallel — they are independent.
  const [credResult, challengeResult] = await Promise.all([
    query(
      `SELECT u.id AS user_id, u.username, u.srp_salt, u.srp_verifier
       FROM   devices d
       JOIN   users   u ON u.id = d.user_id
       WHERE  d.id = $1 AND d.revoked = FALSE`,
      [req.deviceId]
    ),
    query(
      "DELETE FROM srp_challenges WHERE device_id = $1 AND flow = 'password_change' AND expires_at > NOW() RETURNING srp_server_secret",
      [req.deviceId]
    ),
  ])

  const creds = credResult.rows[0]
  if (!creds) {
    console.warn('password_change_confirm: device/user not found', { device_id: req.deviceId })
    return res.status(401).json({ error: 'Authentication failed' })
  }

  const challenge = challengeResult.rows[0]
  if (!challenge) {
    console.warn('password_change_confirm: no valid challenge', { device_id: req.deviceId })
    return res.status(401).json({ error: 'Authentication failed' })
  }

  let serverSession
  try {
    serverSession = await srp.deriveSession(
      challenge.srp_server_secret,
      clientPublicEphemeral,
      creds.srp_salt,
      creds.username,
      creds.srp_verifier,
      clientSessionProof
    )
  } catch (err) {
    console.warn('password_change_confirm: SRP proof mismatch', {
      device_id: req.deviceId,
      reason: err?.message,
    })
    return res.status(401).json({ error: 'Authentication failed' })
  }

  // Old password verified — update credentials.
  await query(
    'UPDATE users SET srp_salt = $1, srp_verifier = $2 WHERE id = $3',
    [new_salt, new_verifier, creds.user_id]
  )

  await revokeSessionKey(req.deviceId)

  console.info('password_change_confirm: password changed', { device_id: req.deviceId })
  res.json({ serverSessionProof: serverSession.proof })
}
