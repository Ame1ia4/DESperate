import { createHmac, createHash, hkdfSync, timingSafeEqual } from 'node:crypto'
import { query } from '../database/db.js'
import { UUID_RE, HMAC_HEX_LEN } from '../constants/auth.js'
import { consumeSessionKey } from '../state/session_keys.js'

export async function requireAuth(req, res, next) {
  const deviceId = req.headers['x-device-id']
  const proof    = req.headers['x-session-proof']

  if (typeof deviceId !== 'string' || !UUID_RE.test(deviceId))
    return res.status(401).json({ error: 'Authentication required' })

  if (typeof proof !== 'string' || proof.length !== HMAC_HEX_LEN || !/^[0-9a-f]+$/i.test(proof))
    return res.status(401).json({ error: 'Authentication required' })

  const { rows } = await query(
    'SELECT 1 FROM devices WHERE id = $1 AND revoked = FALSE',
    [deviceId]
  )
  if (!rows.length) return res.status(401).json({ error: 'Authentication required' })

  const keyHex = consumeSessionKey(deviceId)
  if (!keyHex) return res.status(401).json({ error: 'Authentication required' })

  // auth_key = HKDF-SHA256(K, salt="", info="session-auth", length=32)
  const authKey = hkdfSync('sha256', Buffer.from(keyHex, 'hex'), '', 'session-auth', 32)

  // proof = HMAC-SHA256(auth_key, method:path:hex(SHA256(body)))
  const rawBody  = req.body !== undefined ? JSON.stringify(req.body) : ''
  const bodyHash = createHash('sha256').update(rawBody).digest('hex')
  const message  = `${req.method}:${req.path}:${bodyHash}`
  const expected = createHmac('sha256', authKey).update(message).digest('hex')

  const expBuf = Buffer.from(expected, 'hex')
  const gotBuf = Buffer.from(proof.toLowerCase(), 'hex')
  if (!timingSafeEqual(expBuf, gotBuf))
    return res.status(401).json({ error: 'Authentication required' })

  req.deviceId = deviceId
  next()
}
