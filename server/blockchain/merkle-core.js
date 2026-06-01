// Canonical Merkle leaf + tree rules shared by the server and the
// standalone trustless verification page.
//
// PIN THESE EXACTLY — any divergence between server and page breaks
// the interop invariant (server root must equal page-recomputed root).
//
// Leaf  = keccak256(ciphertext) — AEAD ciphertext-with-tag bytes ONLY.
//         No nonce, AD, id, timestamp, or concatenation.
// Tree  = merkletreejs { sortPairs: false, duplicateOdd: false }
//         Insertion order preserved; an odd leaf is PROMOTED UNCHANGED.
// Proof = ordered [{position:'left'|'right', data:'0x…'}]
//         Positional because sortPairs:false — order matters.
//
// Node: bare import 'merkletreejs' resolved from node_modules.
// Browser: resolved via import map → esm.sh (see verification-page/index.html).

import { MerkleTree } from 'merkletreejs'
import { ethers } from 'ethers'

export const MERKLE_OPTIONS = {
  sortPairs:    false,
  duplicateOdd: false,
}

// keccak256 that merkletreejs can use as its hash fn (Buffer → Buffer).
function keccakBuf(data) {
  const hex = ethers.keccak256(data instanceof Uint8Array ? data : new Uint8Array(data))
  return Buffer.from(hex.slice(2), 'hex')
}

// computeLeaf(ciphertextBytes) → '0x' + 64 hex chars
// ciphertextBytes may be a Buffer, Uint8Array, or hex string.
export function computeLeaf(ciphertextBytes) {
  if (typeof ciphertextBytes === 'string') {
    const clean = ciphertextBytes.startsWith('0x') ? ciphertextBytes : '0x' + ciphertextBytes
    return ethers.keccak256(ethers.getBytes(clean))
  }
  return ethers.keccak256(ciphertextBytes instanceof Uint8Array
    ? ciphertextBytes
    : new Uint8Array(ciphertextBytes))
}

// buildTree(leafHexes) → MerkleTree instance
// leafHexes: array of '0x…' 66-char strings in insertion order.
export function buildTree(leafHexes) {
  const leaves = leafHexes.map(h => Buffer.from(h.replace(/^0x/i, ''), 'hex'))
  return new MerkleTree(leaves, keccakBuf, MERKLE_OPTIONS)
}

// computeRoot(leafHexes) → '0x' + 64 hex chars
export function computeRoot(leafHexes) {
  if (leafHexes.length === 0) throw new Error('computeRoot: empty leaf array')
  return '0x' + buildTree(leafHexes).getRoot().toString('hex')
}

// getProof(leafHexes, index) → [{position:'left'|'right', data:'0x…'}]
export function getProof(leafHexes, index) {
  const tree = buildTree(leafHexes)
  const leafBuf = Buffer.from(leafHexes[index].replace(/^0x/i, ''), 'hex')
  return tree.getProof(leafBuf, index).map(p => ({
    position: p.position,
    data:      '0x' + p.data.toString('hex'),
  }))
}

// verifyProof(leafHex, proof, rootHex) → boolean
// proof: [{position:'left'|'right', data:'0x…'}]
export function verifyProof(leafHex, proof, rootHex) {
  const tree   = new MerkleTree([], keccakBuf, MERKLE_OPTIONS)
  const leafBuf = Buffer.from(leafHex.replace(/^0x/i, ''), 'hex')
  const rootBuf = Buffer.from(rootHex.replace(/^0x/i, ''), 'hex')
  const proofBufs = proof.map(p => ({
    position: p.position,
    data:      Buffer.from(p.data.replace(/^0x/i, ''), 'hex'),
  }))
  return tree.verify(proofBufs, leafBuf, rootBuf)
}
