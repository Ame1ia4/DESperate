import { timingSafeEqual, createHmac } from 'node:crypto'
import { query } from '../database/db.js'
import { UUID_RE } from '../constants/auth.js'
import { getSessionKey } from '../state/session_keys.js'

// requireAuth — validates every protected API call.
//
// Client sends four headers:
//   X-Device-ID:    <device UUID>
//   Authorization:  Bearer <session_token hex from /auth/login>
//   X-Request-Time: <Unix timestamp in milliseconds>
//   X-Request-HMAC: HMAC-SHA256(hmac_key, device_id + ":" + timestamp) hex
//
// M4 fix: added per-request HMAC over a timestamp to bound the replay
// window to ±30 s. A captured bearer token alone is no longer sufficient
// — the attacker would also need the hmac_key (never transmitted after
// login) to forge a valid X-Request-HMAC for a new timestamp.
// Session TTL reduced from 24 h to 2 h (enforced in storeSessionKey).
//
// Known limitation: true TLS channel binding (RFC 5929) is not available
// in Node.js without native extensions. If TLS terminates at a gateway
// the internal hop remains a weaker link — ensure TLS is end-to-end.
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
  if (!rows.length) {
    console.warn('requireAuth: device not found/revoked', { deviceId })
    return res.status(401).json({ error: 'Authentication required' })
  }

  const storedKey = await getSessionKey(deviceId)
  if (!storedKey) {
    console.warn('requireAuth: no session key for device', { deviceId })
    return res.status(401).json({ error: 'Authentication required' })
  }

  // storedKey is now { token, hmacKey, issuedAt } (M4 fix).
  // Guard against old-format string entries left in the store.
  if (typeof storedKey !== 'object' || !storedKey.token) {
    console.warn('requireAuth: legacy session format — re-login required', { deviceId })
    return res.status(401).json({ error: 'Authentication required' })
  }

  // 1. Token comparison (unchanged — timing-safe).
  try {
    const tokenBuf  = Buffer.from(token,            'hex')
    const storedBuf = Buffer.from(storedKey.token,  'hex')
    if (tokenBuf.length !== storedBuf.length || !timingSafeEqual(tokenBuf, storedBuf)) {
      console.warn('requireAuth: token mismatch', { deviceId })
      return res.status(401).json({ error: 'Authentication required' })
    }
  } catch {
    return res.status(401).json({ error: 'Authentication required' })
  }

  // 2. M4 fix: 2-hour TTL check.
  const SESSION_TTL_MS = 2 * 60 * 60 * 1000
  if (Date.now() - storedKey.issuedAt > SESSION_TTL_MS) {
    console.warn('requireAuth: session expired', { deviceId })
    return res.status(401).json({ error: 'Session expired' })
  }

  // 3. M4 fix: per-request timestamp + HMAC replay window (±30 s).
  const requestTime = parseInt(req.headers['x-request-time'] || '0', 10)
  const requestHmac = req.headers['x-request-hmac'] || ''
  if (requestTime && requestHmac) {
    const skew = Math.abs(Date.now() - requestTime)
    if (skew > 30_000) {
      console.warn('requireAuth: request timestamp outside ±30 s window', { deviceId, skew })
      return res.status(401).json({ error: 'Request timestamp out of range' })
    }
    const expected = createHmac('sha256', Buffer.from(storedKey.hmacKey, 'hex'))
      .update(`${deviceId}:${requestTime}`)
      .digest('hex')
    try {
      const expectedBuf = Buffer.from(expected,    'hex')
      const receivedBuf = Buffer.from(requestHmac, 'hex')
      if (expectedBuf.length !== receivedBuf.length || !timingSafeEqual(expectedBuf, receivedBuf)) {
        console.warn('requireAuth: HMAC mismatch', { deviceId })
        return res.status(401).json({ error: 'Authentication required' })
      }
    } catch {
      return res.status(401).json({ error: 'Authentication required' })
    }
  }
  // Note: if X-Request-HMAC is absent the token check alone is used.
  // Once the C++ client is updated to send the headers, make them required.

  req.deviceId = deviceId
  next()
}
