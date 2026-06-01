// ⚠️  SECURITY GAP (interim only) ─────────────────────────────────────────────
// This middleware identifies the device via a plain x-device-id header.
// That header is UNAUTHENTICATED: any client can claim any device id and will
// pass the session-expiry check as long as that device has a live session.
//
// This is an accepted interim measure while /auth/verify (SRP round 2) is still
// a stub.  Once /auth/verify lands and establishes a session key K, this MUST
// be replaced by a session-key MAC on every request (e.g. HMAC-SHA256 over the
// canonical request bytes, keyed with K).
//
// Additional risk: TLS terminates at the gateway; gateway→VM is plaintext HTTP,
// so x-device-id is readable/spoofable on that hop as well.
// ─────────────────────────────────────────────────────────────────────────────

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
