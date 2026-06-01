import { srp } from '../../lib/srp.js'
import { query, withTransaction } from '../../database/db.js'

// Round 1 of the password-change flow.
// The caller is already authenticated (requireAuth ran); we use req.deviceId
// so the client does not need to repeat credentials in the body.
//
// Returns the current salt + a fresh server ephemeral B so the client can
// compute M1 (proof of the old password) for round 2.
export async function passwordChangeInit(req, res) {
  const { rows } = await query(
    `SELECT u.id AS user_id, u.srp_salt, u.srp_verifier
     FROM   devices d
     JOIN   users   u ON u.id = d.user_id
     WHERE  d.id = $1 AND d.revoked = FALSE`,
    [req.deviceId]
  )

  if (!rows.length) {
    return res.status(401).json({ error: 'Device not found' })
  }

  const { srp_salt, srp_verifier } = rows[0]

  const serverEphemeral = await srp.generateEphemeral(srp_verifier)

  if (serverEphemeral.secret.length < 64) {
    throw new Error('SRP b too short: need ≥ 256 bits')
  }

  // Atomically replace any existing password-change challenge for this device.
  // Uses flow = 'password_change' so the login flow's challenge (flow = 'login')
  // is not disturbed — the two can coexist on the same device_id.
  await withTransaction(async (client) => {
    await client.query(
      "DELETE FROM srp_challenges WHERE device_id = $1 AND flow = 'password_change'",
      [req.deviceId]
    )
    await client.query(
      "INSERT INTO srp_challenges (device_id, srp_server_secret, flow) VALUES ($1, $2, 'password_change')",
      [req.deviceId, serverEphemeral.secret]
    )
  })

  console.info('password_change_init: challenge issued', { device_id: req.deviceId })
  res.json({ salt: srp_salt, serverPublicEphemeral: serverEphemeral.public })
}
