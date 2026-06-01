import { timingSafeEqual, createHmac } from 'node:crypto'
import { query } from '../database/db.js'
import { UUID_RE } from '../constants/auth.js'
import { getSessionKey } from '../state/session_keys.js'

// Mirror of hkdfSha256 in auth_verify.js — must stay in sync.
// If you extract this to a shared utils/hkdf.js, import from there instead.
function hkdfSha256(ikm, salt, info, length = 32) {
  const prk = createHmac('sha256', salt).update(ikm).digest()
  const infoBuffer = Buffer.isBuffer(info) ? info : Buffer.from(info)
  const t1 = createHmac('sha256', prk)
    .update(infoBuffer)
    .update(Buffer.from([0x01]))
    .digest()
  return t1.slice(0, length)
}

const BEARER_INFO = Buffer.from('bearer-token-v1')

// requireAuth — validates every protected API call.
//
// Client sends two headers:
//   X-Device-ID:    <device UUID registered on this server>
//   Authorization:  Bearer <HKDF(session_key, device_id, "bearer-token-v1")>
//
// The bearer token is derived from the session key at login time and is
// what the client presents on every request. The raw session key K is
// stored server-side only and never transmitted. On each request we
// re-derive the expected token from K and compare in constant time.
//
// Security property: a stolen bearer token from a request log cannot be
// used to recover K. The token is only valid while the session exists
// server-side — invalidating the session (logout, TTL expiry, device
// revocation) immediately invalidates all derived tokens.
export async function requireAuth(req, res, next) {
  const deviceId   = req.headers['x-device-id']
  const authHeader = req.headers['authorization'] || ''

  if (typeof deviceId !== 'string' || !UUID_RE.test(deviceId))
    return res.status(401).json({ error: 'Authentication required' })

  if (!authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Authentication required' })

  const token = authHeader.slice(7).trim()
  if (!token || !/^[0-9a-f]+$/i.test(token))
    return res.status(401).json({ error: 'Authentication required' })

  // Verify device is active and not revoked.
  const { rows } = await query(
    'SELECT 1 FROM devices WHERE id = $1 AND revoked = FALSE',
    [deviceId]
  )
  if (!rows.length) return res.status(401).json({ error: 'Authentication required' })

  // Load the raw session key — stored server-side, never transmitted.
  const storedKey = await getSessionKey(deviceId)
  if (!storedKey) return res.status(401).json({ error: 'Authentication required' })

  // Re-derive the expected bearer token from the stored session key and
  // compare against what the client sent — constant-time comparison.
  //
  // Both sides use HKDF(K, salt=device_id, info="bearer-token-v1", len=32)
  // so the derivation is deterministic for the same K and device_id.
  try {
    const sessionKeyBuf  = Buffer.from(storedKey, 'hex')
    const saltBuf        = Buffer.from(deviceId)
    const expectedToken  = hkdfSha256(sessionKeyBuf, saltBuf, BEARER_INFO, 32)
    const receivedToken  = Buffer.from(token, 'hex')

    // Length must match before timingSafeEqual — both are 32 bytes (64 hex chars)
    // from the same HKDF output, so a mismatch here means a malformed request.
    if (receivedToken.length !== expectedToken.length || !timingSafeEqual(receivedToken, expectedToken))
      return res.status(401).json({ error: 'Authentication required' })
  } catch {
    return res.status(401).json({ error: 'Authentication required' })
  }

  req.deviceId = deviceId
  next()
}
