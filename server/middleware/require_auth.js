import { query } from '../database/db.js'
import { UUID_RE } from '../constants/auth.js'

export async function requireAuth(req, res, next) {
  const deviceId = req.headers['x-device-id']

  if (typeof deviceId !== 'string' || !UUID_RE.test(deviceId)) {
    return res.status(401).json({ error: 'Authentication required' })
  }

  const { rows } = await query(
    `SELECT 1 FROM devices
     WHERE  id            = $1
       AND  srp_expires_at > NOW()
       AND  revoked        = FALSE`,
    [deviceId]
  )

  if (!rows.length) {
    return res.status(401).json({ error: 'Authentication required' })
  }

  req.deviceId = deviceId
  next()
}
