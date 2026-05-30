import { query, withTransaction } from '../../database/db.js'
import { verifyDualSignature } from '../../utils/crypto.js'
import { parseHex } from '../../utils/parseHex.js'
import { consumeNonce } from './nonce.js'
import { isValidUsername } from '../../utils/validate.js'
import {
  HEX_RE,
  SRP_SALT_HEX, SRP_VERIFIER_HEX,
  DEVICE_NAME_MAX,
  X25519_PUB_BYTES, SIGNING_PUB_BYTES, DUAL_SIG_BYTES,
  MLKEM_PUB_BYTES, ED25519_SIG_BYTES,
} from '../../constants/auth.js'

export async function register(req, res) {
  const { username, bundle } = req.body

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Invalid username' })
  }

  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    return res.status(400).json({ error: 'Invalid bundle' })
  }

  const {
    srp_salt, srp_verifier,
    idk_classical_pub, identity_signing_pub,
    signed_prekey_pub, signed_prekey_signature,
    nonce, nonce_signature,
    idk_pq_pub, device_name,
  } = bundle

  if (
    typeof srp_salt !== 'string' ||
    srp_salt.length !== SRP_SALT_HEX ||
    !HEX_RE.test(srp_salt)
  ) {
    return res.status(400).json({ error: 'Invalid srp_salt' })
  }

  if (
    typeof srp_verifier !== 'string' ||
    srp_verifier.length !== SRP_VERIFIER_HEX ||
    !HEX_RE.test(srp_verifier)
  ) {
    return res.status(400).json({ error: 'Invalid srp_verifier' })
  }

  if (
    device_name !== undefined &&
    device_name !== null &&
    (typeof device_name !== 'string' || device_name.length > DEVICE_NAME_MAX)
  ) {
    return res.status(400).json({ error: 'Invalid device_name' })
  }

  // Keys are validated by hex encoding and byte length only — no structural curve/point validation.
  let idkClassicalPub, signingPub, signedPrekeyPub, signedPrekeySig, nonceSig
  let idkPqPub = null

  try {
    idkClassicalPub = parseHex(idk_classical_pub,       X25519_PUB_BYTES,  'idk_classical_pub')
    signingPub      = parseHex(identity_signing_pub,    SIGNING_PUB_BYTES, 'identity_signing_pub')
    signedPrekeyPub = parseHex(signed_prekey_pub,       X25519_PUB_BYTES,  'signed_prekey_pub')
    signedPrekeySig = parseHex(signed_prekey_signature, DUAL_SIG_BYTES,    'signed_prekey_signature')
    nonceSig        = parseHex(nonce_signature,         DUAL_SIG_BYTES,    'nonce_signature')

    if (idk_pq_pub != null) {
      idkPqPub = parseHex(idk_pq_pub, MLKEM_PUB_BYTES, 'idk_pq_pub')
    }

  } catch (err) {
    if (err.status === 400) return res.status(400).json({ error: err.message })
    throw err
  }

  if (
    typeof nonce !== 'string' ||
    nonce.length !== 64 ||
    !HEX_RE.test(nonce)
  ) {
    return res.status(400).json({ error: 'Invalid nonce' })
  }

  // consumeNonce is single-use — always deletes the entry so a rejected
  // registration cannot retry with the same nonce.
  if (!consumeNonce(nonce)) {
    return res.status(400).json({ error: 'Invalid nonce' })
  }

  const nonceBytes = Buffer.from(nonce, 'hex')

  // Verify proof-of-possession of the signing key (Sesame §6.3).
  if (!verifyDualSignature(
    signingPub, nonceBytes,
    nonceSig.subarray(0, ED25519_SIG_BYTES),
    nonceSig.subarray(ED25519_SIG_BYTES)
  )) {
    return res.status(400).json({ error: 'Invalid key bundle' })
  }

  // Verify the signed prekey is authenticated by the same signing key.
  if (!verifyDualSignature(
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
        [username, srp_salt, srp_verifier]
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
          device_name ?? null,
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
    nonceSig.fill(0)
    idkPqPub?.fill(0)
  }

  return res.status(201).json({ deviceId })
}
