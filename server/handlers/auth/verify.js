import { query } from '../../database/db.js'
import { createSession } from '../../sessions.js'
import { verifyDualSignature } from '../../utils/crypto.js'
import { parseHex } from '../../utils/parseHex.js'
import { ED25519_SIG_BYTES, MLDSA_SIG_BYTES } from '../../constants/auth.js'

// Verifies the signed challenge and issues a session token on success.
export async function verify(req, res) {
  const { device_id, ed25519_sig, ml_dsa_sig } = req.body

  if (typeof device_id !== 'string' || !device_id) {
    return res.status(400).json({ error: 'Invalid device_id' })
  }

  // TODO: const nonce = consumeChallenge(device_id) — requires sessions.js (separate PR)
  // TODO: if (!nonce) return res.status(401).json({ error: 'Authentication failed' })

  let ed25519SigBuf, mlDsaSigBuf
  try {
    ed25519SigBuf = parseHex(ed25519_sig, ED25519_SIG_BYTES, 'ed25519_sig')
    mlDsaSigBuf   = parseHex(ml_dsa_sig,  MLDSA_SIG_BYTES,   'ml_dsa_sig')
  } catch {
    // Treat malformed sigs as auth failures — don't distinguish for oracle prevention
    return res.status(401).json({ error: 'Authentication failed' })
  }

  const { rows } = await query(
    'SELECT id, user_id, identity_signing_pub FROM devices WHERE id = $1 AND revoked = FALSE',
    [device_id]
  )

  if (rows.length === 0) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  const { id: deviceId, user_id: userId, identity_signing_pub: signingPub } = rows[0]

  // TODO: pass nonce as message once sessions.js lands
  // Verify both signatures — identical error on any failure (oracle prevention)
  if (!await verifyDualSignature(signingPub, nonce, ed25519SigBuf, mlDsaSigBuf)) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  await query('UPDATE devices SET last_seen = NOW() WHERE id = $1', [deviceId])

  const token = createSession(deviceId, userId)
  return res.json({ token })
}
