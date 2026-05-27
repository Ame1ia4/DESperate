import crypto from 'crypto'
import argon2 from 'argon2'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { query, withTransaction } from '../database/db.js'
import {
  createChallenge,
  consumeChallenge,
  createSession,
  deleteSession,
  deleteAllSessionsForDevice,
} from '../sessions.js'
import { verifyDualSignature } from '../utils/crypto.js'


// ── Key size constants ──────────────────────────────────────────────────────

const ED25519_PUB_BYTES  = 32
const MLDSA_PUB_BYTES    = 1952
const SIGNING_PUB_BYTES  = 1984   // ED25519_PUB_BYTES + MLDSA_PUB_BYTES
const ED25519_SIG_BYTES  = 64
const MLDSA_SIG_BYTES    = ml_dsa65.signatureLen
const MLKEM_PUB_BYTES    = ml_kem768.publicKeyLen
const X25519_PUB_BYTES   = 32

// ── Argon2id parameters (OWASP 2025 minimum) ───────────────────────────────

const ARGON2_MEMORY_COST = 19456  // 19MB
const ARGON2_TIME_COST   = 2
const ARGON2_PARALLELISM = 1

// ── Input validation ────────────────────────────────────────────────────────

const USERNAME_REGEX = /^[a-zA-Z0-9_]+$/
const USERNAME_MIN   = 3
const USERNAME_MAX   = 50
const PASSWORD_MIN   = 12

// Parse a hex string and verify its decoded length matches expectedBytes.
// Throws a 400 error on any mismatch so callers can return early.
function parseHex(hex, expectedBytes, fieldName) {
  if (typeof hex !== 'string' || hex.length !== expectedBytes * 2) {
    const err = new Error(`Invalid ${fieldName}`)
    err.status = 400
    throw err
  }
  const buf = Buffer.from(hex, 'hex')
  if (buf.length !== expectedBytes) {
    const err = new Error(`Invalid ${fieldName}`)
    err.status = 400
    throw err
  }
  return buf
}

// ── POST /auth/register ─────────────────────────────────────────────────────

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
    (typeof device.device_name !== 'string' || device.device_name.length > 100)
  ) {
    return res.status(400).json({ error: 'Invalid device_name' })
  }

  if (typeof device.identity_fingerprint !== 'string' || device.identity_fingerprint.length === 0) {
    return res.status(400).json({ error: 'Invalid identity_fingerprint' })
  }

  // Parse and validate all binary key bundle fields
  let idkClassicalPub, signingPub, signedPrekeyPub, signedPrekeySig
  let idkPqPub = null, lastResortOpkPub = null, lastResortOpkSig = null
  let opks

  try {
    idkClassicalPub = parseHex(device.idk_classical_pub,      X25519_PUB_BYTES,                 'idk_classical_pub')
    signingPub      = parseHex(device.identity_signing_pub,   SIGNING_PUB_BYTES,                 'identity_signing_pub')
    signedPrekeyPub = parseHex(device.signed_prekey_pub,      X25519_PUB_BYTES,                 'signed_prekey_pub')
    signedPrekeySig = parseHex(device.signed_prekey_signature, ED25519_SIG_BYTES + MLDSA_SIG_BYTES, 'signed_prekey_signature')

    if (device.idk_pq_pub != null) {
      idkPqPub = parseHex(device.idk_pq_pub, MLKEM_PUB_BYTES, 'idk_pq_pub')
    }

    if (device.last_resort_opk_pub != null) {
      lastResortOpkPub = parseHex(device.last_resort_opk_pub,       X25519_PUB_BYTES,                 'last_resort_opk_pub')
      lastResortOpkSig = parseHex(device.last_resort_opk_signature, ED25519_SIG_BYTES + MLDSA_SIG_BYTES, 'last_resort_opk_signature')
    }

    if (!Array.isArray(device.opks)) {
      return res.status(400).json({ error: 'Invalid opks' })
    }
    opks = device.opks.map((hex, i) => parseHex(hex, X25519_PUB_BYTES, `opks[${i}]`))

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

  // Verify last-resort OPK if provided — same signing key, different message
  if (lastResortOpkPub && lastResortOpkSig) {
    if (!await verifyDualSignature(
      signingPub, lastResortOpkPub,
      lastResortOpkSig.subarray(0, ED25519_SIG_BYTES),
      lastResortOpkSig.subarray(ED25519_SIG_BYTES)
    )) {
      return res.status(400).json({ error: 'Invalid key bundle' })
    }
  }

  const passwordHash = await argon2.hash(password, {
    type:        argon2.argon2id,
    memoryCost:  ARGON2_MEMORY_COST,
    timeCost:    ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
  })

  const { rows: taken } = await query(
    'SELECT 1 FROM users WHERE username = $1',
    [username]
  )
  if (taken.length > 0) {
    return res.status(409).json({ error: 'Registration failed' })
  }

  try {
    const deviceId = await withTransaction(async (client) => {
      const { rows: [user] } = await client.query(
        'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
        [username, passwordHash]
      )

      const { rows: [deviceRow] } = await client.query(
        `INSERT INTO devices (
          user_id, device_name,
          idk_classical_pub, idk_pq_pub,
          identity_signing_pub, identity_fingerprint,
          signed_prekey_pub, signed_prekey_signature,
          last_resort_opk_pub, last_resort_opk_signature
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
        [
          user.id,
          device.device_name ?? null,
          idkClassicalPub,
          idkPqPub,
          signingPub,
          device.identity_fingerprint,
          signedPrekeyPub,
          signedPrekeySig,
          lastResortOpkPub,
          lastResortOpkSig,
        ]
      )

      if (opks.length > 0) {
        // Build multi-row insert: ($1, $2), ($1, $3), ... — device_id is always $1
        const placeholders = opks.map((_, i) => `($1, $${i + 2})`).join(', ')
        await client.query(
          `INSERT INTO one_time_prekeys (device_id, opk_pub) VALUES ${placeholders}`,
          [deviceRow.id, ...opks]
        )
      }

      return deviceRow.id
    })

    return res.status(201).json({ deviceId })

  } catch (err) {
    if (err.cause?.code === '23505') {
      return res.status(409).json({ error: 'Registration failed' })
    }
    throw err
  }
}

// ── POST /auth/challenge ────────────────────────────────────────────────────

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
    return res.status(404).json({ error: 'Device not found' })
  }

  const nonce = createChallenge(device_id)
  return res.json({ nonce: nonce.toString('hex') })
}

// ── POST /auth/verify ───────────────────────────────────────────────────────

export async function verify(req, res) {
  const { device_id, ed25519_sig, ml_dsa_sig } = req.body

  if (typeof device_id !== 'string' || !device_id) {
    return res.status(400).json({ error: 'Invalid device_id' })
  }

  // Consume challenge first — single use, enforces TTL
  const nonce = consumeChallenge(device_id)
  if (!nonce) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

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

  // Verify both signatures over the nonce — identical error on any failure (oracle prevention)
  if (!await verifyDualSignature(signingPub, nonce, ed25519SigBuf, mlDsaSigBuf)) {
    return res.status(401).json({ error: 'Authentication failed' })
  }

  await query('UPDATE devices SET last_seen = NOW() WHERE id = $1', [deviceId])

  const token = createSession(deviceId, userId)
  return res.json({ token })
}

// ── POST /auth/logout ───────────────────────────────────────────────────────

export async function logout(req, res) {
  deleteSession(req.sessionToken)
  return res.json({ message: 'Logged out' })
}

// ── POST /auth/logout-all ───────────────────────────────────────────────────

export async function logoutAll(req, res) {
  deleteAllSessionsForDevice(req.deviceId)
  return res.json({ message: 'Logged out' })
}
