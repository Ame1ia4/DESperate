import { createSRPServer } from 'js-srp6a'
import { createHmac } from 'node:crypto'
import { query } from '../database/db.js'
import { storeSessionKey } from '../state/session_keys.js'
import { isValidUsername, isValidUUID, isValidClientPublicEphemeral } from '../utils/validate.js'
import { HEX_RE, SRP_SESSION_PROOF_HEX } from '../constants/auth.js'

const srp = createSRPServer('SHA-256', 3072)

// HKDF-SHA256 extract+expand — Node's built-in crypto module does not expose
// HKDF directly before Node 15, so we implement it via HMAC which is
// available everywhere. For Node 15+ you can replace this with
// crypto.hkdfSync('sha256', ikm, salt, info, length).
//
// This is used only to derive the bearer token from the SRP session key.
// The session key K stays secret server-side; only the derived token is
// transmitted in headers and logs.
function hkdfSha256(ikm, salt, info, length = 32) {
  // Extract: PRK = HMAC-SHA256(salt, IKM)
  const prk = createHmac('sha256', salt).update(ikm).digest()

  // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
  // Single block sufficient for 32 bytes (one SHA-256 output).
  const infoBuffer = Buffer.isBuffer(info) ? info : Buffer.from(info)
  const t1 = createHmac('sha256', prk)
    .update(infoBuffer)
    .update(Buffer.from([0x01]))
    .digest()

  return t1.slice(0, length)
}

// Domain-separated info label for bearer token derivation.
// Changing this string invalidates all existing tokens — version it if needed.
const BEARER_INFO = Buffer.from('bearer-token-v1')

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

  // Derive the bearer token from the session key via HKDF.
  //
  // The raw SRP session key K is stored server-side and never transmitted.
  // The bearer token — HKDF(K, salt=device_id, info="bearer-token-v1") —
  // is what the client presents in the Authorization header.
  //
  // Security property: a stolen bearer token from a request log cannot be
  // used to derive K, so the attacker cannot forge the HKDF output for a
  // different info string or reuse it after session expiry.
  const sessionKeyBuf = Buffer.from(serverSession.key, 'hex')
  const saltBuf       = Buffer.from(device_id)   // device_id as HKDF salt
  const bearerToken   = hkdfSha256(sessionKeyBuf, saltBuf, BEARER_INFO, 32).toString('hex')

  // Store the raw session key server-side — never the bearer token.
  await storeSessionKey(device_id, serverSession.key)

  console.info('auth_login: session established', { username, device_id })

  res.json({
    serverSessionProof: serverSession.proof,
    bearerToken,          // client stores this and sends it as Authorization: Bearer <token>
  })
}
