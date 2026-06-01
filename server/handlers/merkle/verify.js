import { query } from '../../database/db.js'
import { getProof } from '../../blockchain/merkle-core.js'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// Compute the three-value client status for a message.
// Returns { status, ...material } where status is one of:
//   'nothing'            — gated by deletion or no leaf exists
//   'pending'            — leaf/root not yet confirmed on-chain
//   'stored-on-blockchain' — root confirmed; includes copy material
async function getMessageStatus(msgId, userId, deviceId) {
  // Check global deletion gate (deleted_for_everyone)
  const { rows: msgRows } = await query(
    `SELECT m.id, m.deleted_at, m.conversation_id,
            encode(m.ciphertext, 'hex') AS ciphertext_hex
     FROM messages m
     WHERE m.id = $1`,
    [msgId]
  )
  if (msgRows.length === 0) return { status: 'nothing' }

  const msg = msgRows[0]

  if (msg.deleted_at !== null) return { status: 'nothing' }

  // Check per-user hidden gate
  const { rows: hiddenRows } = await query(
    `SELECT 1 FROM message_hidden WHERE msg_id = $1 AND user_id = $2`,
    [msgId, userId]
  )
  if (hiddenRows.length > 0) return { status: 'nothing' }

  // Fetch leaf + root
  const { rows: leafRows } = await query(
    `SELECT l.leaf_hash, l.leaf_index, l.state AS leaf_state,
            r.id AS root_id, r.merkle_root, r.tx_hash, r.block_timestamp,
            r.state AS root_state
     FROM merkle_leaves l
     LEFT JOIN merkle_roots r ON r.id = l.merkle_root_id
     WHERE l.msg_id = $1`,
    [msgId]
  )

  if (leafRows.length === 0) return { status: 'nothing' }

  const leaf = leafRows[0]

  if (!leaf.root_id || leaf.root_state !== 'confirmed') {
    return { status: 'pending' }
  }

  // Build inclusion proof — fetch all leaves for this root ordered by index
  const { rows: allLeaves } = await query(
    `SELECT leaf_hash FROM merkle_leaves
     WHERE merkle_root_id = $1
     ORDER BY leaf_index ASC`,
    [leaf.root_id]
  )

  const leafHexes = allLeaves.map(l => l.leaf_hash.trim())
  const proof     = getProof(leafHexes, leaf.leaf_index)

  return {
    status:          'stored-on-blockchain',
    ciphertext:      '0x' + msg.ciphertext_hex,
    tx_hash:         leaf.tx_hash?.trim(),
    merkle_root:     leaf.merkle_root?.trim(),
    block_timestamp: leaf.block_timestamp,
    leaf_hash:       leaf.leaf_hash?.trim(),
    leaf_index:      leaf.leaf_index,
    proof,
  }
}

export async function verifyHandler(req, res) {
  const { id: msgId } = req.params

  if (!msgId || !UUID_RE.test(msgId)) {
    return res.status(400).json({ error: 'Invalid message id' })
  }

  // Membership check — requester must be a conversation participant
  const { rows: memberRows } = await query(
    `SELECT 1
     FROM messages m
     JOIN conversation_members cm
       ON cm.conversation_id = m.conversation_id
     WHERE m.id = $1 AND cm.user_id = $2`,
    [msgId, req.userId]
  )
  if (memberRows.length === 0) {
    return res.status(403).json({ error: 'Not a participant in this conversation' })
  }

  const result = await getMessageStatus(msgId, req.userId, req.deviceId)
  res.json(result)
}
