import { query } from '../../database/db.js'
import { buildTree } from '../../blockchain/merkle-core.js'

const HEX64_RE = /^(0x)?[0-9a-f]{64}$/i

export async function proofHandler(req, res) {
  const { leaf, root } = req.body

  if (!leaf || !HEX64_RE.test(leaf)) {
    return res.status(400).json({ error: 'leaf must be a 64-char hex string' })
  }
  if (!root || !HEX64_RE.test(root)) {
    return res.status(400).json({ error: 'root must be a 64-char hex string' })
  }

  const normLeaf = leaf.startsWith('0x') ? leaf.toLowerCase() : '0x' + leaf.toLowerCase()
  const normRoot = root.startsWith('0x') ? root.toLowerCase() : '0x' + root.toLowerCase()

  const { rows: rootRows } = await query(
    `SELECT id FROM merkle_roots
     WHERE lower(merkle_root) = $1 AND state = 'confirmed'`,
    [normRoot]
  )

  if (rootRows.length === 0) {
    return res.json({ verified: false, reason: 'Root not found or not yet confirmed' })
  }

  const rootId = rootRows[0].id

  const { rows: leafRows } = await query(
    `SELECT leaf_hash FROM merkle_leaves
     WHERE merkle_root_id = $1
     ORDER BY leaf_index ASC`,
    [rootId]
  )

  if (leafRows.length === 0) {
    return res.json({ verified: false, reason: 'No leaves found for this root' })
  }

  const leafHexes = leafRows.map(r => r.leaf_hash.trim())
  const leafIndex = leafHexes.findIndex(l => l.toLowerCase() === normLeaf)

  if (leafIndex === -1) {
    return res.json({ verified: false, reason: 'Leaf not found in this root' })
  }

  const tree           = buildTree(leafHexes)
  const recomputedRoot = '0x' + tree.getRoot().toString('hex')
  const verified       = recomputedRoot.toLowerCase() === normRoot

  res.json({ verified })
}
