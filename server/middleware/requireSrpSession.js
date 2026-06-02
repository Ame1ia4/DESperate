// INTERIM ONLY: x-device-id is unauthenticated — any client can claim any device id.
// Replace with a session-key MAC (HMAC-SHA256 keyed with K) once /auth/verify lands.
// Also: TLS terminates at the gateway; gateway→VM hop is plaintext, so the header is spoofable there too.

import { query } from '../database/db.js'
import { UUID_RE } from '../constants/auth.js'

export async function requireSrpSession(req, res, next) {
  const deviceId = req.headers['x-device-id']

  if (!deviceId || !UUID_RE.test(deviceId)) {
    return res.status(401).json({ error: 'Missing or invalid x-device-id header' })
  }

  const { rows } = await query(
    `SELECT user_id, revoked, srp_verified_at, srp_expires_at
     FROM devices
     WHERE id = $1`,
    [deviceId]
  )

  const device = rows[0]

  if (!device) {
    return res.status(401).json({ error: 'Device not found' })
  }

  if (device.revoked) {
    return res.status(401).json({ error: 'Device has been revoked' })
  }

  if (!device.srp_verified_at) {
    return res.status(401).json({ error: 'Device session not established — complete SRP handshake' })
  }

  if (new Date(device.srp_expires_at) <= new Date()) {
    return res.status(401).json({ error: 'Device session expired — reauthenticate' })
  }

  req.deviceId = deviceId
  req.userId   = device.user_id
  next()
}
