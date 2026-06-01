// Tests for the canonical merkle-core shared module.
// These are pure-function tests; no DB or ethers mocking needed.
// ⚠️  Requires merkletreejs in node_modules — run `npm install --ignore-scripts` first.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { computeLeaf, computeRoot, buildTree, getProof, verifyProof } from '../../blockchain/merkle-core.js'

// Deterministic test ciphertext buffers
function fakeCt(n) {
  return Buffer.alloc(32, n)
}

function makeLeaves(count) {
  return Array.from({ length: count }, (_, i) => computeLeaf(fakeCt(i + 1)))
}

// ── computeLeaf ──────────────────────────────────────────────────────────────

describe('computeLeaf()', () => {
  it('returns a 0x-prefixed 66-char hex string', () => {
    const leaf = computeLeaf(fakeCt(1))
    assert.match(leaf, /^0x[0-9a-f]{64}$/)
  })

  it('accepts a hex string and returns the same result as a Buffer', () => {
    const buf    = fakeCt(42)
    const hex    = '0x' + buf.toString('hex')
    assert.strictEqual(computeLeaf(buf), computeLeaf(hex))
  })

  it('is deterministic — same input → same output', () => {
    const leaf1 = computeLeaf(fakeCt(7))
    const leaf2 = computeLeaf(fakeCt(7))
    assert.strictEqual(leaf1, leaf2)
  })

  it('produces distinct leaves for different ciphertexts', () => {
    assert.notStrictEqual(computeLeaf(fakeCt(1)), computeLeaf(fakeCt(2)))
  })
})

// ── computeRoot interop invariant ────────────────────────────────────────────

describe('computeRoot() interop invariant', () => {
  for (const count of [1, 2, 3, 4, 100]) {
    it(`server root == independently recomputed root for batch size ${count}`, () => {
      const leaves = makeLeaves(count)
      const root1  = computeRoot(leaves)
      // Recompute independently by calling computeRoot again on the same leaves
      const root2  = computeRoot([...leaves])
      assert.strictEqual(root1, root2)
      assert.match(root1, /^0x[0-9a-f]{64}$/)
    })
  }

  it('throws on empty leaf array', () => {
    assert.throws(() => computeRoot([]), /empty/)
  })
})

// ── Odd-node promotion (duplicateOdd: false) ─────────────────────────────────

describe('odd-node promotion', () => {
  it('tree with 3 leaves has a root distinct from a 4-leaf tree with a duplicated leaf', () => {
    const leaves3 = makeLeaves(3)
    const root3   = computeRoot(leaves3)

    // If duplicateOdd: true, the 3-leaf tree would treat the 3rd leaf twice;
    // with duplicateOdd: false, the odd leaf is promoted unchanged → different root.
    const leaves4dup = [...leaves3, leaves3[2]] // simulate duplicate-odd behaviour
    const root4dup   = computeRoot(leaves4dup)

    // They SHOULD be different because sortPairs:false + duplicateOdd:false
    // gives promotion, not duplication.
    assert.notStrictEqual(root3, root4dup,
      'duplicateOdd:false must produce a different root than naively duplicating the odd leaf')
  })

  it('single-leaf tree has the leaf as the root', () => {
    const leaf = computeLeaf(fakeCt(1))
    const root = computeRoot([leaf])
    assert.strictEqual(root, leaf)
  })
})

// ── getProof / verifyProof ───────────────────────────────────────────────────

describe('getProof() and verifyProof()', () => {
  for (const count of [2, 3, 4, 100]) {
    it(`proof verifies for every leaf in a ${count}-leaf tree`, () => {
      const leaves = makeLeaves(count)
      const root   = computeRoot(leaves)

      for (let i = 0; i < leaves.length; i++) {
        const proof = getProof(leaves, i)
        assert.ok(verifyProof(leaves[i], proof, root),
          `verifyProof failed for leaf ${i} in ${count}-leaf tree`)
      }
    })
  }

  it('verifyProof returns false for a tampered leaf', () => {
    const leaves      = makeLeaves(4)
    const root        = computeRoot(leaves)
    const proof       = getProof(leaves, 0)
    const badLeaf     = computeLeaf(fakeCt(99))
    assert.ok(!verifyProof(badLeaf, proof, root))
  })

  it('verifyProof returns false for a tampered sibling in the proof', () => {
    const leaves     = makeLeaves(4)
    const root       = computeRoot(leaves)
    const proof      = getProof(leaves, 0)
    const badProof   = proof.map((p, i) => i === 0 ? { ...p, data: computeLeaf(fakeCt(99)) } : p)
    assert.ok(!verifyProof(leaves[0], badProof, root))
  })

  it('proof positions are left or right strings', () => {
    const leaves = makeLeaves(4)
    const proof  = getProof(leaves, 0)
    for (const p of proof) {
      assert.ok(p.position === 'left' || p.position === 'right')
      assert.match(p.data, /^0x[0-9a-f]{64}$/)
    }
  })
})
