import { query } from '../../database/db.js'
import { createChallenge } from '../../sessions.js'

// Issues a one-time nonce for a device to sign as proof of identity.
export async function challenge(req, res) {
  const { device_id } = req.body

  if (typeof device_id !== 'string' || !device_id) {
    return res.status(400).json({ error: 'Invalid device_id' })
  }

  const { rows } = await query(
    'SELECT id FROM devices WHERE id = $1 AND revoked = FALSE',
    [device_id]
  )

  if (rows.length === 0) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  const nonce = createChallenge(device_id)
  return res.json({ nonce: nonce.toString('hex') })
}
