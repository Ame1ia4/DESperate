import { query } from '../../database/db.js'
import { buildTree } from '../../blockchain/merkle-core.js'

const HEX64_RE = /^(0x)?[0-9a-f]{64}$/i

// POST /blockchain/verify-leaf
// Body: { leaf: '0x...', root: '0x...' }
//
// The verification page sends:
//   leaf = keccak256(ciphertext), computed in the browser
//   root = merkle root read from the on-chain HashStored event in step 1
//
// This endpoint rebuilds the Merkle tree from all stored leaves for that root
// and returns whether the submitted leaf is provably included.
// The caller trusts the pass/fail result; the on-chain root check in step 1
// is what makes the overall flow trustworthy.

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

  // Find the root row
  const { rows: rootRows } = await query(
    `SELECT id FROM merkle_roots
     WHERE lower(merkle_root) = $1 AND state = 'confirmed'`,
    [normRoot]
  )

  if (rootRows.length === 0) {
    return res.json({ verified: false, reason: 'Root not found or not yet confirmed' })
  }

  const rootId = rootRows[0].id

  // Fetch all leaves for this root in insertion order
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

  // Check the submitted leaf is even in our set before building the tree
  const leafIndex = leafHexes.findIndex(l => l.toLowerCase() === normLeaf)

  if (leafIndex === -1) {
    return res.json({ verified: false, reason: 'Leaf not found in this root' })
  }

  // Rebuild the tree and verify the proof
  const tree    = buildTree(leafHexes)
  const recomputedRoot = '0x' + tree.getRoot().toString('hex')

  const verified = recomputedRoot.toLowerCase() === normRoot

  res.json({ verified })
}
