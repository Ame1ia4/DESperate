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
    console.warn('auth_verify: device/user not found', { device_id, username })
    return res.status(401).json({ error: 'Authentication failed' })
  }

  const challengeResult = await query(
    'DELETE FROM srp_challenges WHERE device_id = $1 AND expires_at > NOW() RETURNING srp_server_secret',
    [device_id]
  )
  const challenge = challengeResult.rows[0]

  if (!challenge) {
    console.warn('auth_verify: no valid challenge for device', { device_id })
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
  } catch (err) {
    console.warn('auth_verify: SRP proof mismatch', { device_id, username, reason: err?.message })
    return res.status(401).json({ error: 'Authentication failed' })
  }

  // M4 fix: derive both a session token and a separate HMAC signing key
  // from SRP K using domain-separated HKDF info strings. The token is
  // what the client presents; the signing key is stored server-side and
  // used to verify per-request timestamps (replay window check).
  //
  // TTL reduced from 24 h to 2 h. The client must re-authenticate when
  // the session expires. Short TTL limits the damage window if a token
  // is captured on an internal hop where TLS is terminated at a gateway.
  //
  // Full TLS channel binding (RFC 5929 tls-unique) is not available in
  // Node.js without native extensions; the timestamp+HMAC approach is the
  // practical mitigation within the existing stack. Document as known
  // limitation in the design doc.
  const kBuf = Buffer.from(serverSession.key, 'hex')

  const sessionTokenBuf = hkdfSync('sha256', kBuf, Buffer.alloc(0), 'session-token', 32)
  const session_token   = Buffer.from(sessionTokenBuf).toString('hex')

  const hmacKeyBuf = hkdfSync('sha256', kBuf, Buffer.alloc(0), 'session-hmac-key', 32)
  const hmac_key   = Buffer.from(hmacKeyBuf).toString('hex')

  // Store token, HMAC key, and issue time together.
  // storeSessionKey stores { token, hmacKey, issuedAt } under device_id.
  const issuedAt = Date.now()
  await storeSessionKey(device_id, { token: session_token, hmacKey: hmac_key, issuedAt })

  console.info('auth_login: session established', { username, device_id })
  // Return hmac_key to the client so it can sign per-request timestamps.
  // The client must include X-Request-Time (Unix ms) and
  // X-Request-HMAC: HMAC-SHA256(hmac_key, device_id + ":" + timestamp) on every request.
  res.json({ serverSessionProof: serverSession.proof, session_token, hmac_key })
}
