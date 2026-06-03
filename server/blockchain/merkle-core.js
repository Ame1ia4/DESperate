// PIN THESE EXACTLY — any divergence between server and verification page breaks
// the interop invariant (server root must equal page-recomputed root).
//
// Leaf = keccak256(ciphertext) — AEAD ciphertext-with-tag bytes ONLY.
// Tree = merkletreejs { sortPairs: false, duplicateOdd: false }
//        Odd leaf is PROMOTED UNCHANGED (not duplicated). Order matters.

import { MerkleTree } from 'merkletreejs'
import { ethers } from 'ethers'

export const MERKLE_OPTIONS = {
  sortPairs:    false,
  duplicateOdd: false,
}

function keccakBuf(data) {
  const hex = ethers.keccak256(data instanceof Uint8Array ? data : new Uint8Array(data))
  return Buffer.from(hex.slice(2), 'hex')
}

// M2 fix: bind the leaf to its context so a server cannot move a valid
// ciphertext hash from one conversation or sender to another.
//
// Old leaf = keccak256(ciphertext)
// New leaf = keccak256(message_id || conversation_id || sender_device_id || ciphertext)
//
// All fields are length-prefixed (4-byte LE uint32) to prevent boundary
// confusion between adjacent variable-length inputs.
//
// The verification page must use the same construction — update verification.html
// to accept and encode the three context fields alongside the ciphertext.
//
// BREAKING: existing roots computed with the old scheme will not verify.
// Document this as a migration cut-over in the design doc.
export function computeLeaf(ciphertextBytes, { messageId, conversationId, senderDeviceId } = {}) {
  // Encode a string field as: 4-byte LE length prefix || UTF-8 bytes.
  // A missing/empty field encodes as four zero bytes (length = 0).
  function encodeField(s) {
    if (!s) return Buffer.alloc(4)
    const b = Buffer.from(s, 'utf8')
    const len = Buffer.alloc(4)
    len.writeUInt32LE(b.length, 0)
    return Buffer.concat([len, b])
  }

  const ctBuf = typeof ciphertextBytes === 'string'
    ? Buffer.from(ciphertextBytes.replace(/^0x/i, ''), 'hex')
    : Buffer.from(ciphertextBytes instanceof Uint8Array ? ciphertextBytes : new Uint8Array(ciphertextBytes))

  const ctLen = Buffer.alloc(4)
  ctLen.writeUInt32LE(ctBuf.length, 0)

  const preimage = Buffer.concat([
    encodeField(messageId),
    encodeField(conversationId),
    encodeField(senderDeviceId),
    ctLen,
    ctBuf,
  ])

  return ethers.keccak256(preimage)
}

export function buildTree(leafHexes) {
  const leaves = leafHexes.map(h => Buffer.from(h.replace(/^0x/i, ''), 'hex'))
  return new MerkleTree(leaves, keccakBuf, MERKLE_OPTIONS)
}

export function computeRoot(leafHexes) {
  if (leafHexes.length === 0) throw new Error('computeRoot: empty leaf array')
  return '0x' + buildTree(leafHexes).getRoot().toString('hex')
}

export function getProof(leafHexes, index) {
  const tree = buildTree(leafHexes)
  const leafBuf = Buffer.from(leafHexes[index].replace(/^0x/i, ''), 'hex')
  return tree.getProof(leafBuf, index).map(p => ({
    position: p.position,
    data:      '0x' + p.data.toString('hex'),
  }))
}

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

// queryFilterChunked — wraps contract.queryFilter in 9 000-block chunks to
// stay within drpc free-tier limits (10 000 block max per eth_getLogs call).
// Stops early once at least one matching log is found.
const CHUNK = 9_000
export async function queryFilterChunked(contract, filter, fromBlock, toBlock) {
  const logs = []
  for (let from = fromBlock; from <= toBlock; from += CHUNK) {
    const to = Math.min(from + CHUNK - 1, toBlock)
    const chunk = await contract.queryFilter(filter, from, to)
    logs.push(...chunk)
    if (logs.length > 0) break
  }
  return logs
}
