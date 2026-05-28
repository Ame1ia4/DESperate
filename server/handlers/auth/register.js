import argon2 from 'argon2'
import { query, withTransaction } from '../../database/db.js'
import { verifyDualSignature } from '../../utils/crypto.js'
import { parseHex } from '../../utils/parseHex.js'
import {
  ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM,
  USERNAME_REGEX, USERNAME_MIN, USERNAME_MAX,
  PASSWORD_MIN, DEVICE_NAME_MAX,
  X25519_PUB_BYTES, SIGNING_PUB_BYTES, DUAL_SIG_BYTES,
  MLKEM_PUB_BYTES, ED25519_SIG_BYTES,
} from '../../constants/auth.js'

// Registers a new user with their first device and key bundle.
export async function register(req, res) {
  const { username, password, device } = req.body

  if (
    typeof username !== 'string' ||
    !USERNAME_REGEX.test(username) ||
    username.length < USERNAME_MIN ||
    username.length > USERNAME_MAX
  ) {
    return res.status(400).json({ error: 'Invalid username' })
  }

  if (typeof password !== 'string' || password.length < PASSWORD_MIN) {
    return res.status(400).json({ error: 'Invalid password' })
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

  // Parse and validate all binary key bundle fields
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

  // Verify signed prekey — dual Ed25519 + ML-DSA over signed_prekey_pub
  if (!await verifyDualSignature(
    signingPub, signedPrekeyPub,
    signedPrekeySig.subarray(0, ED25519_SIG_BYTES),
    signedPrekeySig.subarray(ED25519_SIG_BYTES)
  )) {
    return res.status(400).json({ error: 'Invalid key bundle' })
  }

  // Run in parallel — always hash so timing is identical whether username exists or not
  const [{ rows: taken }, passwordHash] = await Promise.all([
    query('SELECT 1 FROM users WHERE username = $1', [username]),
    argon2.hash(password, {
      type:        argon2.argon2id,
      memoryCost:  ARGON2_MEMORY_COST,
      timeCost:    ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
    }),
  ])
  if (taken.length > 0) {
    return res.status(409).json({ error: 'Registration failed' })
  }

  let deviceId
  try {
    deviceId = await withTransaction(async (client) => {
      const { rows: [user] } = await client.query(
        'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
        [username, passwordHash]
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
    // Zero key material from memory — Buffers have fixed addresses so fill(0) is reliable
    idkClassicalPub.fill(0)
    signingPub.fill(0)
    signedPrekeyPub.fill(0)
    signedPrekeySig.fill(0)
    idkPqPub?.fill(0)
  }

  return res.status(201).json({ deviceId })
}
