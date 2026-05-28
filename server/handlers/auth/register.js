import { query, withTransaction } from '../../database/db.js'
import { verifyDualSignature } from '../../utils/crypto.js'
import { parseHex } from '../../utils/parseHex.js'
import {
  SRP_SALT_HEX, SRP_VERIFIER_HEX,
  USERNAME_REGEX, USERNAME_MIN, USERNAME_MAX,
  DEVICE_NAME_MAX,
  X25519_PUB_BYTES, SIGNING_PUB_BYTES, DUAL_SIG_BYTES,
  MLKEM_PUB_BYTES, ED25519_SIG_BYTES,
} from '../../constants/auth.js'

const HEX_RE = /^[0-9a-f]+$/i

export async function register(req, res) {
  const { username, salt, verifier, device } = req.body

  if (
    typeof username !== 'string' ||
    !USERNAME_REGEX.test(username) ||
    username.length < USERNAME_MIN ||
    username.length > USERNAME_MAX
  ) {
    return res.status(400).json({ error: 'Invalid username' })
  }

  if (
    typeof salt !== 'string' ||
    salt.length !== SRP_SALT_HEX ||
    !HEX_RE.test(salt)
  ) {
    return res.status(400).json({ error: 'Invalid salt' })
  }

  if (
    typeof verifier !== 'string' ||
    verifier.length !== SRP_VERIFIER_HEX ||
    !HEX_RE.test(verifier)
  ) {
    return res.status(400).json({ error: 'Invalid verifier' })
  }

  if (!device || typeof device !== 'object' || Array.isArray(device)) {
    return res.status(400).json({ error: 'Invalid device' })
  }

  if (
    device.device_name !== undefined &&
    device.device_name !== null &&
    (typeof device.device_name !== 'string' || device.device_name.length > DEVICE_NAME_MAX)
  ) {
    return res.status(400).json({ error: 'Invalid device_name' })
  }

  let idkClassicalPub, signingPub, signedPrekeyPub, signedPrekeySig
  let idkPqPub = null

  try {
    idkClassicalPub = parseHex(device.idk_classical_pub,       X25519_PUB_BYTES,  'idk_classical_pub')
    signingPub      = parseHex(device.identity_signing_pub,    SIGNING_PUB_BYTES, 'identity_signing_pub')
    signedPrekeyPub = parseHex(device.signed_prekey_pub,       X25519_PUB_BYTES,  'signed_prekey_pub')
    signedPrekeySig = parseHex(device.signed_prekey_signature, DUAL_SIG_BYTES,    'signed_prekey_signature')

    if (device.idk_pq_pub != null) {
      idkPqPub = parseHex(device.idk_pq_pub, MLKEM_PUB_BYTES, 'idk_pq_pub')
    }

  } catch (err) {
    if (err.status === 400) return res.status(400).json({ error: err.message })
    throw err
  }

  if (!await verifyDualSignature(
    signingPub, signedPrekeyPub,
    signedPrekeySig.subarray(0, ED25519_SIG_BYTES),
    signedPrekeySig.subarray(ED25519_SIG_BYTES)
  )) {
    return res.status(400).json({ error: 'Invalid key bundle' })
  }

  const { rows: taken } = await query('SELECT 1 FROM users WHERE username = $1', [username])
  if (taken.length > 0) {
    return res.status(409).json({ error: 'Registration failed' })
  }

  let deviceId
  try {
    deviceId = await withTransaction(async (client) => {
      const { rows: [user] } = await client.query(
        'INSERT INTO users (username, srp_salt, srp_verifier) VALUES ($1, $2, $3) RETURNING id',
        [username, salt, verifier]
      )

      const { rows: [deviceRow] } = await client.query(
        `INSERT INTO devices (
          user_id, device_name,
          idk_classical_pub, idk_pq_pub,
          identity_signing_pub,
          signed_prekey_pub, signed_prekey_signature
        ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [
          user.id,
          device.device_name ?? null,
          idkClassicalPub,
          idkPqPub,
          signingPub,
          signedPrekeyPub,
          signedPrekeySig,
        ]
      )

      return deviceRow.id
    })

  } catch (err) {
    if (err.cause?.code === '23505') {
      return res.status(409).json({ error: 'Registration failed' })
    }
    throw err
  } finally {
    idkClassicalPub.fill(0)
    signingPub.fill(0)
    signedPrekeyPub.fill(0)
    signedPrekeySig.fill(0)
    idkPqPub?.fill(0)
  }

  return res.status(201).json({ deviceId })
}
