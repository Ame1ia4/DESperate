import { withTransaction } from '../../database/db.js'
import { computeLeaf } from '../../blockchain/merkle-core.js'

const HEX_RE         = /^(0x)?[0-9a-f]+$/i
const LEAF_HEX_RE    = /^(0x)?[0-9a-f]{64}$/i
const UUID_RE        = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MAX_CIPHERTEXT = 65_536
const NONCE_BYTES    = 12

export async function sendMessage(req, res) {
  const { conversation_id, ciphertext, nonce, associated_data, client_leaf } = req.body

  if (!conversation_id || !UUID_RE.test(conversation_id)) {
    return res.status(400).json({ error: 'Invalid conversation_id' })
  }

  // Validate hex-encoded byte fields
  if (
    typeof ciphertext     !== 'string' || !HEX_RE.test(ciphertext) ||
    typeof nonce          !== 'string' || !HEX_RE.test(nonce)       ||
    typeof associated_data !== 'string' || !HEX_RE.test(associated_data)
  ) {
    return res.status(400).json({ error: 'ciphertext, nonce, and associated_data must be hex strings' })
  }

  // Strip optional 0x prefix for byte-length checks
  const ctHex = ciphertext.replace(/^0x/i, '')
  const nHex  = nonce.replace(/^0x/i, '')

  if (ctHex.length / 2 > MAX_CIPHERTEXT) {
    return res.status(400).json({ error: `ciphertext exceeds ${MAX_CIPHERTEXT} bytes` })
  }
  if (nHex.length / 2 !== NONCE_BYTES) {
    return res.status(400).json({ error: `nonce must be exactly ${NONCE_BYTES} bytes` })
  }

  if (!client_leaf || !LEAF_HEX_RE.test(client_leaf)) {
    return res.status(400).json({ error: 'client_leaf must be a 32-byte (64-char) hex string' })
  }

  // Recompute leaf server-side and reject on mismatch.
  // This binds ciphertext content to the on-chain anchor and
  // prevents a client from supplying an arbitrary leaf hash.
  const ctBytes   = Buffer.from(ctHex, 'hex')
  const serverLeaf = computeLeaf(ctBytes)
  const normClient = client_leaf.startsWith('0x') ? client_leaf.toLowerCase() : '0x' + client_leaf.toLowerCase()

  if (serverLeaf.toLowerCase() !== normClient) {
    return res.status(400).json({ error: 'client_leaf does not match keccak256(ciphertext)' })
  }

  const result = await withTransaction(async (client) => {
    const msgResult = await client.query(
      `INSERT INTO messages
         (conversation_id, sender_device_id, ciphertext, nonce, associated_data)
       VALUES ($1, $2, decode($3, 'hex'), decode($4, 'hex'), decode($5, 'hex'))
       RETURNING id`,
      [conversation_id, req.deviceId, ctHex, nHex, associated_data.replace(/^0x/i, '')]
    )

    const msgId = msgResult.rows[0].id

    await client.query(
      `INSERT INTO merkle_leaves (leaf_hash, msg_id, state)
       VALUES ($1, $2, 'pending')`,
      [serverLeaf, msgId]
    )

    return msgId
  })

  res.status(201).json({ id: result, status: 'pending' })
}
