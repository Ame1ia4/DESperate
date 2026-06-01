import { timingSafeEqual } from 'node:crypto'
import { query } from '../database/db.js'
import { UUID_RE } from '../constants/auth.js'
import { getSessionKey } from '../state/session_keys.js'

// requireAuth — validates every protected API call.
//
// Client sends two headers:
//   X-Device-ID:    <device UUID registered on this server>
//   Authorization:  Bearer <session key hex returned by /auth/login>
//
// The session key is established by the SRP login flow and stored
// server-side with a 24-hour TTL (session_keys.js).  The client
// receives an identical copy via the Python crypto service's
// srp_verify response and sends it as a static bearer token.
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

  try {
    const tokenBuf = Buffer.from(token,     'hex')
    const keyBuf   = Buffer.from(storedKey, 'hex')
    if (tokenBuf.length !== keyBuf.length || !timingSafeEqual(tokenBuf, keyBuf)) {
      console.warn('requireAuth: token mismatch', { deviceId, tokenLen: token.length, keyLen: storedKey.length })
      return res.status(401).json({ error: 'Authentication required' })
    }
  } catch {
    return res.status(401).json({ error: 'Authentication required' })
  }

  req.deviceId = deviceId
  next()
}
