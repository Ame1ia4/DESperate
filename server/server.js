import 'dotenv/config'
import crypto from 'crypto'
import { readFileSync } from 'fs'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { verifyRoot } from './blockchain/merkle-verify.js'
import { startBlockchainWorker } from './blockchain/publisher.js'
import { register, registrationNonce } from './handlers/auth/index.js'
import { authInit } from './middleware/auth_init.js'
import { authVerify } from './middleware/auth_verify.js'
import { requireAuth } from './middleware/require_auth.js'
import { query, withTransaction, registerShutdownSignals } from './database/db.js'
import { revokeSessionKey } from './state/session_keys.js'
import { UUID_RE } from './constants/auth.js'
import { computeLeaf } from './blockchain/merkle-core.js'
import { verifyHandler } from './handlers/merkle/verify.js'
import { proofHandler } from './handlers/merkle/proof.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

const verificationHtmlTemplate = readFileSync(
  join(__dirname, 'blockchain', 'verification.html'), 'utf-8'
)

const app = express()

app.use((_req, res, next) => {
  res.locals.nonce = crypto.randomBytes(32).toString('base64')
  next()
})

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'strict-dynamic'",
        (_req, res) => `'nonce-${res.locals.nonce}'`,
        'https:',
      ],
      styleSrc:  ["'self'", 'https://fonts.googleapis.com'],
      fontSrc:   ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:    ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri:   ["'self'"],
      formAction: ["'self'"],
    },
  },
}))
app.set('trust proxy', 1)
app.use(cors({ origin: `https://${process.env.SUBDOMAIN}` }))
app.use(express.json({ limit: '2mb' }))

app.get('/health', (_, res) => res.json({ status: 'ok' }))

const authLimiter    = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 })
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })
app.use(generalLimiter)

// ── Public routes ──
const serveVerification = (req, res) => {
  const html = verificationHtmlTemplate.replace(/<script/g, `<script nonce="${res.locals.nonce}"`)
  res.type('html').send(html)
}
app.get('/', serveVerification)
app.get('/verification.html', serveVerification)

app.use(express.static(join(__dirname, 'blockchain')))

const HEX64_RE = /^(0x)?[0-9a-f]{64}$/i
app.get('/api/blockchain/verify', async (req, res) => {
  const { root } = req.query
  if (!root || !HEX64_RE.test(root))
    return res.status(400).json({ error: 'root must be a 64-character hex string' })
  try {
    const result = await verifyRoot(root)
    res.json(result)
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// ── Auth ──
app.get('/auth/nonce',    authLimiter, registrationNonce)
app.post('/auth/register', authLimiter, register)
app.post('/auth/init',     authLimiter, authInit)
app.post('/auth/login',    authLimiter, authVerify)

// ── Public key bundle fetch (protected) ──
// Returns the public PQXDH bundle for a username so a peer can initiate a session.
app.get('/keys/:username', requireAuth, async (req, res) => {
  const { username } = req.params
  if (!username || username.length > 50)
    return res.status(400).json({ error: 'Invalid username' })

  const { rows } = await query(
    `SELECT
       d.id                                    AS device_id,
       encode(d.idk_classical_pub,     'hex')  AS ik_classical_pub,
       encode(d.idk_pq_pub,            'hex')  AS ik_kem_pub,
       encode(d.identity_signing_pub,  'hex')  AS ik_sig_pub,
       encode(d.signed_prekey_pub,     'hex')  AS spk_pub,
       encode(d.signed_prekey_signature,'hex') AS spk_sig
     FROM devices d
     JOIN users   u ON u.id = d.user_id
     WHERE u.username = $1
       AND d.revoked  = FALSE
     LIMIT 1`,
    [username]
  )
  if (!rows.length) return res.status(404).json({ error: 'User not found' })

  // Fetch one unused X25519 + ML-KEM OPK pair (matching opk_id) and mark both as used.
  // Atomicity prevents two concurrent initiators from claiming the same OPK.
  const { rows: opkRows } = await query(
    `WITH chosen AS (
        SELECT opk_id
        FROM   one_time_prekeys
        WHERE  device_id = $1
          AND  used      = FALSE
          AND  key_type  = 'x25519'
        ORDER  BY created_at ASC
        LIMIT  1
        FOR UPDATE SKIP LOCKED
     ),
     mark_used AS (
        UPDATE one_time_prekeys
        SET    used = TRUE, used_at = NOW()
        WHERE  device_id = $1
          AND  opk_id IN (SELECT opk_id FROM chosen)
        RETURNING opk_id, key_type, encode(opk_pub, 'hex') AS opk_pub
     )
     SELECT * FROM mark_used`,
    [rows[0].device_id]
  )

  const opks_x25519 = opkRows
    .filter(r => r.key_type === 'x25519')
    .map(r => ({ opk_id: r.opk_id, opk_pub: r.opk_pub }))
  const opks_kem = opkRows
    .filter(r => r.key_type === 'ml-kem-1024')
    .map(r => ({ opk_id: r.opk_id, opk_pub: r.opk_pub }))

  const { device_id: _omit, ...bundle } = rows[0]
  res.json({
    ...bundle,
    spk_id:      1,
    opks_x25519,
    opks_kem,
  })
})

// OPK upload — accepts paired X25519 + ML-KEM-1024 one-time prekeys.
// opks_x25519 and opks_kem must be equal-length arrays with matching opk_ids.
app.post('/keys/opks', requireAuth, async (req, res) => {
  const { opks_x25519, opks_kem } = req.body

  if (
    !Array.isArray(opks_x25519) ||
    !Array.isArray(opks_kem) ||
    opks_x25519.length !== opks_kem.length
  ) return res.status(400).json({ error: 'opks_x25519 and opks_kem must be equal-length arrays' })

  let uploaded = 0
  await withTransaction(async (client) => {
    for (let i = 0; i < opks_x25519.length; i++) {
      const x = opks_x25519[i]
      const k = opks_kem[i]
      if (typeof x?.opk_id !== 'number' || x.opk_id !== k?.opk_id)
        throw new Error(`OPK ID mismatch at index ${i}`)
      const xBuf = Buffer.from(x.opk_pub, 'hex')
      const kBuf = Buffer.from(k.opk_pub, 'hex')
      if (xBuf.length !== 32)
        throw new Error(`X25519 OPK at index ${i} must be 32 bytes`)
      if (kBuf.length !== 1568)
        throw new Error(`ML-KEM-1024 OPK at index ${i} must be 1568 bytes`)
      await client.query(
        `INSERT INTO one_time_prekeys (device_id, opk_id, opk_pub, key_type)
         VALUES ($1, $2, $3, 'x25519')
         ON CONFLICT (device_id, opk_id, key_type) DO NOTHING`,
        [req.deviceId, x.opk_id, xBuf]
      )
      await client.query(
        `INSERT INTO one_time_prekeys (device_id, opk_id, opk_pub, key_type)
         VALUES ($1, $2, $3, 'ml-kem-1024')
         ON CONFLICT (device_id, opk_id, key_type) DO NOTHING`,
        [req.deviceId, k.opk_id, kBuf]
      )
      uploaded++
    }
  })

  res.json({ uploaded })
})

// ── Conversations ──

// List all conversations the authenticated user is a member of.
app.get('/conversations', requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT
       c.id,
       u2.username                              AS participant,
       d2.id                                    AS device_id,
       encode(d2.identity_signing_pub, 'hex')   AS fingerprint,
       c.created_at                             AS updated_at,
       0                                        AS unread_count,
       ''                                       AS last_message
     FROM conversations       c
     JOIN conversation_members cm1 ON cm1.conversation_id = c.id
     JOIN users                u1  ON u1.id  = cm1.user_id
     JOIN conversation_members cm2 ON cm2.conversation_id = c.id
                                  AND cm2.user_id != cm1.user_id
     JOIN users                u2  ON u2.id  = cm2.user_id
     JOIN devices              d2  ON d2.user_id = u2.id
                                  AND d2.revoked = FALSE
     WHERE u1.id = (
       SELECT user_id FROM devices WHERE id = $1
     )
     ORDER BY c.created_at DESC`,
    [req.deviceId]
  )
  res.json({ conversations: rows })
})

// Create (or return existing) conversation with another user.
app.post('/conversations', requireAuth, async (req, res) => {
  const { other_username } = req.body
  if (!other_username || typeof other_username !== 'string')
    return res.status(400).json({ error: 'other_username required' })

  // Resolve current user + other user
  const selfResult = await query(
    'SELECT user_id FROM devices WHERE id = $1', [req.deviceId]
  )
  if (!selfResult.rows.length) return res.status(401).json({ error: 'Device not found' })
  const selfUserId = selfResult.rows[0].user_id

  const otherResult = await query(
    'SELECT id FROM users WHERE username = $1', [other_username]
  )
  if (!otherResult.rows.length) return res.status(404).json({ error: 'User not found' })
  const otherUserId = otherResult.rows[0].id

  if (selfUserId === otherUserId)
    return res.status(400).json({ error: 'Cannot create conversation with yourself' })

  // Return existing DM if one already exists between these two users.
  const existing = await query(
    `SELECT c.id FROM conversations c
     JOIN conversation_members cm1 ON cm1.conversation_id = c.id AND cm1.user_id = $1
     JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id = $2
     LIMIT 1`,
    [selfUserId, otherUserId]
  )
  if (existing.rows.length) {
    return res.json({ conversationId: existing.rows[0].id })
  }

  const conversationId = await withTransaction(async (client) => {
    const { rows: [conv] } = await client.query(
      'INSERT INTO conversations DEFAULT VALUES RETURNING id'
    )
    await client.query(
      'INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2), ($1, $3)',
      [conv.id, selfUserId, otherUserId]
    )
    return conv.id
  })

  res.status(201).json({ conversationId })
})

// ── Messages ──

// Send an encrypted message — stores it and fans out to recipient devices.
app.post('/messages', requireAuth, async (req, res) => {
  const { conversation_id, ciphertext, nonce, initiation_bundle, sender_ik_sig_pub } = req.body

  if (!conversation_id || !ciphertext || !nonce)
    return res.status(400).json({ error: 'conversation_id, ciphertext, and nonce required' })

  // Validate that the sender is a member of this conversation.
  const memberCheck = await query(
    `SELECT 1 FROM conversation_members cm
     JOIN devices d ON d.user_id = cm.user_id
     WHERE cm.conversation_id = $1 AND d.id = $2`,
    [conversation_id, req.deviceId]
  )
  if (!memberCheck.rows.length)
    return res.status(403).json({ error: 'Not a member of this conversation' })

  let ciphertextBuf, nonceBuf
  try {
    ciphertextBuf = Buffer.from(ciphertext, 'hex')
    nonceBuf      = Buffer.from(nonce, 'hex')
  } catch {
    return res.status(400).json({ error: 'Invalid hex encoding' })
  }

  if (nonceBuf.length !== 12)
    return res.status(400).json({ error: 'nonce must be 12 bytes' })

  // Match the DB CHECK (octet_length(ciphertext) <= 65536) with a clean 4xx
  // instead of letting an oversized payload hit the constraint as a 500.
  if (ciphertextBuf.length > 65536)
    return res.status(413).json({ error: 'ciphertext exceeds 64 KiB limit' })

  // associated_data for AEAD = conversation_id bytes
  const associatedData = Buffer.from(conversation_id)

  const messageId = await withTransaction(async (client) => {
    const { rows: [msg] } = await client.query(
      `INSERT INTO messages
         (conversation_id, sender_device_id, ciphertext, nonce, associated_data, sender_ik_sig_pub)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, created_at`,
      [conversation_id, req.deviceId, ciphertextBuf, nonceBuf, associatedData, sender_ik_sig_pub || null]
    )

    const leafHash = computeLeaf(ciphertextBuf)
    await client.query(
      `INSERT INTO merkle_leaves (leaf_hash, msg_id, state) VALUES ($1, $2, 'pending')`,
      [leafHash, msg.id]
    )

    // Find recipient devices (all members except sender).
    const { rows: recipients } = await client.query(
      `SELECT d.id AS device_id
       FROM   conversation_members cm
       JOIN   devices d ON d.user_id = cm.user_id
       WHERE  cm.conversation_id = $1
         AND  d.id      != $2
         AND  d.revoked  = FALSE`,
      [conversation_id, req.deviceId]
    )

    // Fan out to each recipient device.
    const queueMeta = Buffer.from(JSON.stringify({ initiation_bundle: initiation_bundle ?? null }))
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

    for (const r of recipients) {
      // msg_sequence is filled by the message_queue_msg_sequence_seq default —
      // atomic, strictly increasing, never colliding.
      await client.query(
        `INSERT INTO message_queue
           (msg_id, recipient_device_id, associated_data, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [msg.id, r.device_id, queueMeta, expiresAt]
      )
    }

    return msg.id
  })

  res.status(201).json({ id: messageId })
})

// Pull pending (undelivered) messages for the authenticated device.
app.get('/messages/pending', requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT
       m.id                                    AS id,
       m.conversation_id,
       m.sender_device_id,
       encode(m.ciphertext, 'hex')             AS ciphertext,
       encode(m.nonce,      'hex')             AS nonce,
       m.sender_ik_sig_pub,
       mq.id                                   AS queue_id,
       mq.associated_data,
       m.created_at
     FROM message_queue mq
     JOIN messages m ON m.id = mq.msg_id
     WHERE mq.recipient_device_id = $1
       AND mq.delivery_state      = 'pending'
       AND mq.expires_at          > NOW()
       AND m.deleted_at           IS NULL
     ORDER BY mq.msg_sequence ASC
     LIMIT 100`,
    [req.deviceId]
  )

  const envelopes = rows.map(r => {
    let initiationBundle = null
    try {
      const meta = JSON.parse(r.associated_data.toString())
      initiationBundle = meta.initiation_bundle ?? null
    } catch { /* ignore parse errors */ }

    return {
      id:                r.id,
      conversation_id:   r.conversation_id,
      sender_device_id:  r.sender_device_id,
      recipient_device_id: req.deviceId,
      ciphertext:        r.ciphertext,
      nonce:             r.nonce,
      sender_ik_sig_pub: r.sender_ik_sig_pub,
      initiation_bundle: initiationBundle,
      created_at:        r.created_at,
    }
  })

  res.json({ envelopes })
})

// Acknowledge delivery — marks the queue entry as delivered.
app.post('/messages/:id/ack', requireAuth, async (req, res) => {
  const messageId = req.params.id
  await query(
    `UPDATE message_queue
     SET    delivery_state = 'acknowledged',
            acknowledged_at = NOW()
     WHERE  msg_id = $1
       AND  recipient_device_id = $2
       AND  delivery_state NOT IN ('acknowledged')`,
    [messageId, req.deviceId]
  )
  res.json({ acknowledged: true })
})

// Conversation message history — returns messages in a conversation, oldest-first.
// Supports cursor-based pagination via ?before=<message_id>.
app.get('/conversations/:id/messages', requireAuth, async (req, res) => {
  const conversationId = req.params.id
  if (!UUID_RE.test(conversationId))
    return res.status(400).json({ error: 'Invalid conversation_id' })

  // Verify requesting device is a member of this conversation.
  const memberCheck = await query(
    `SELECT 1 FROM conversation_members cm
     JOIN devices d ON d.user_id = cm.user_id
     WHERE cm.conversation_id = $1 AND d.id = $2`,
    [conversationId, req.deviceId]
  )
  if (!memberCheck.rows.length)
    return res.status(403).json({ error: 'Not a member of this conversation' })

  const { before } = req.query
  let rows

  if (before) {
    if (!UUID_RE.test(before))
      return res.status(400).json({ error: 'Invalid before cursor' })

    const result = await query(
      `SELECT
         m.id,
         m.sender_device_id,
         encode(m.ciphertext, 'hex') AS ciphertext,
         encode(m.nonce,      'hex') AS nonce,
         m.created_at,
         (m.sender_device_id = $3)   AS is_mine
       FROM messages m
       WHERE m.conversation_id = $1
         AND m.deleted_at IS NULL
         AND m.created_at < (
           SELECT created_at FROM messages WHERE id = $2
         )
       ORDER BY m.created_at ASC
       LIMIT 50`,
      [conversationId, before, req.deviceId]
    )
    rows = result.rows
  } else {
    const result = await query(
      `SELECT
         m.id,
         m.sender_device_id,
         encode(m.ciphertext, 'hex') AS ciphertext,
         encode(m.nonce,      'hex') AS nonce,
         m.created_at,
         (m.sender_device_id = $2)   AS is_mine
       FROM messages m
       WHERE m.conversation_id = $1
         AND m.deleted_at IS NULL
       ORDER BY m.created_at ASC
       LIMIT 50`,
      [conversationId, req.deviceId]
    )
    rows = result.rows
  }

  res.json({ messages: rows })
})

// Download a single message by ID.
app.get('/messages/:id', requireAuth, async (req, res) => {
  const messageId = req.params.id
  if (!UUID_RE.test(messageId))
    return res.status(400).json({ error: 'Invalid message id' })

  const { rows } = await query(
    `SELECT
       m.id,
       m.conversation_id,
       m.sender_device_id,
       encode(m.ciphertext, 'hex') AS ciphertext,
       encode(m.nonce,      'hex') AS nonce,
       m.created_at,
       m.deleted_at
     FROM messages m
     WHERE m.id = $1`,
    [messageId]
  )
  if (!rows.length) return res.status(404).json({ error: 'Message not found' })
  if (rows[0].deleted_at) return res.status(410).json({ error: 'Message has been deleted' })

  // Verify device is a member of this conversation.
  const memberCheck = await query(
    `SELECT 1 FROM conversation_members cm
     JOIN devices d ON d.user_id = cm.user_id
     WHERE cm.conversation_id = $1 AND d.id = $2`,
    [rows[0].conversation_id, req.deviceId]
  )
  if (!memberCheck.rows.length)
    return res.status(403).json({ error: 'Not a member of this conversation' })

  const { deleted_at: _omit, ...message } = rows[0]
  res.json(message)
})

// Soft-delete a message — only the sender may delete.
app.delete('/messages/:id', requireAuth, async (req, res) => {
  const messageId = req.params.id
  if (!UUID_RE.test(messageId))
    return res.status(400).json({ error: 'Invalid message id' })

  const { rowCount } = await query(
    `UPDATE messages
     SET deleted_at           = NOW(),
         deleted_by_device_id = $2
     WHERE id               = $1
       AND sender_device_id IN (
             SELECT id FROM devices
             WHERE user_id = (
               SELECT user_id FROM devices WHERE id = $2
             )
           )
       AND deleted_at IS NULL`,
    [messageId, req.deviceId]
  )

  if (rowCount === 0)
    return res.status(403).json({ error: 'Not the sender or message already deleted' })

  res.json({ deleted: true })
})

// Revoke a pending queue entry so a recipient cannot receive the message.
app.post('/messages/:id/revoke', requireAuth, async (req, res) => {
  const messageId = req.params.id
  if (!UUID_RE.test(messageId))
    return res.status(400).json({ error: 'Invalid message id' })

  const { recipient_device_id } = req.body
  if (typeof recipient_device_id !== 'string' || !UUID_RE.test(recipient_device_id))
    return res.status(400).json({ error: 'recipient_device_id required' })

  // Verify the caller is the sender of this message.
  const senderCheck = await query(
    `SELECT 1 FROM messages
     WHERE id = $1
       AND sender_device_id IN (
             SELECT id FROM devices
             WHERE user_id = (
               SELECT user_id FROM devices WHERE id = $2
             )
           )`,
    [messageId, req.deviceId]
  )
  if (!senderCheck.rows.length)
    return res.status(403).json({ error: 'Not the sender of this message' })

  const { rowCount } = await query(
    `DELETE FROM message_queue
     WHERE msg_id              = $1
       AND recipient_device_id = $2
       AND delivery_state      = 'pending'`,
    [messageId, recipient_device_id]
  )

  if (rowCount > 0) {
    res.json({ revoked: true, already_delivered: false })
  } else {
    res.json({ revoked: false, already_delivered: true })
  }
})

// Change SRP credentials (salt + verifier) for the authenticated user.
app.patch('/auth/password', authLimiter, requireAuth, async (req, res) => {
  const { new_salt, new_verifier } = req.body

  if (typeof new_salt !== 'string' || !/^[0-9a-f]{64}$/i.test(new_salt))
    return res.status(400).json({ error: 'new_salt must be 64 hex characters' })
  if (typeof new_verifier !== 'string' || !/^[0-9a-f]{1,768}$/i.test(new_verifier))
    return res.status(400).json({ error: 'new_verifier must be up to 768 hex characters' })

  const userResult = await query(
    'SELECT user_id FROM devices WHERE id = $1',
    [req.deviceId]
  )
  if (!userResult.rows.length) return res.status(401).json({ error: 'Device not found' })

  await query(
    'UPDATE users SET srp_salt = $1, srp_verifier = decode($2, \'hex\') WHERE id = $3',
    [new_salt, new_verifier, userResult.rows[0].user_id]
  )

  res.json({ updated: true })
})

// Revoke a device belonging to the authenticated user. device_id is required;
// the target must share a user with the caller. Revocation is instant: the
// device is flagged revoked (requireAuth rejects it on its next request) and
// its session key is purged from cache + DB so the bearer token dies at once.
app.post('/devices/revoke', requireAuth, async (req, res) => {
  const { device_id } = req.body
  if (typeof device_id !== 'string' || !UUID_RE.test(device_id))
    return res.status(400).json({ error: 'device_id required' })

  // Target must belong to the same user as the caller.
  const { rows } = await query(
    `SELECT 1
     FROM devices target
     JOIN devices caller ON caller.user_id = target.user_id
     WHERE target.id = $1 AND caller.id = $2`,
    [device_id, req.deviceId]
  )
  if (!rows.length) return res.status(404).json({ error: 'Device not found' })

  await query('UPDATE devices SET revoked = TRUE WHERE id = $1', [device_id])
  await revokeSessionKey(device_id)

  res.json({ revoked: true })
})

app.get('/messages/:id/blockchain-verify', requireAuth, verifyHandler)
app.post('/blockchain/verify-leaf',        proofHandler)

// ── 404 ──
app.use((_, res) => res.status(404).json({ error: 'Not found' }))

// ── Global error handler ──
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: 'Internal server error' })
})

const PORT = process.env.PORT ?? 3000
const server = app.listen(PORT, () => console.log(`Server running on :${PORT}`))

startBlockchainWorker()

registerShutdownSignals(server)
