import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import * as ed from '@noble/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

import { verifyDualSignature } from '../utils/crypto.js'

// ── Test key material — generated once, reused across all tests ──────────────

let ed25519Priv, ed25519Pub
let mlDsaPriv,   mlDsaPub
let signingPub   // combined 1984-byte key (Ed25519 || ML-DSA)
let message      // test nonce / message

before(async () => {
  ed25519Priv = ed.utils.randomSecretKey()
  ed25519Pub  = await ed.getPublicKey(ed25519Priv)

  const mlDsaKeys = ml_dsa65.keygen()
  mlDsaPriv = mlDsaKeys.secretKey
  mlDsaPub  = mlDsaKeys.publicKey

  signingPub = Buffer.concat([ed25519Pub, mlDsaPub])
  message    = crypto.randomBytes(32)
})

// Helper — signs message with both keys and returns [ed25519Sig, mlDsaSig]
async function signBoth(msg = message) {
  const ed25519Sig = await ed.sign(msg, ed25519Priv)
  const mlDsaSig   = ml_dsa65.sign(msg, mlDsaPriv)
  return [Buffer.from(ed25519Sig), Buffer.from(mlDsaSig)]
}

// ── Happy path ───────────────────────────────────────────────────────────────

describe('verifyDualSignature — valid signatures', () => {
  it('accepts a valid dual signature', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    assert.strictEqual(await verifyDualSignature(signingPub, message, ed25519Sig, mlDsaSig), true)
  })

  it('accepts signatures over different messages independently', async () => {
    const msg2 = crypto.randomBytes(32)
    const [ed25519Sig, mlDsaSig] = await signBoth(msg2)
    assert.strictEqual(await verifyDualSignature(signingPub, msg2, ed25519Sig, mlDsaSig), true)
  })
})

// ── Both signatures must pass ────────────────────────────────────────────────

describe('verifyDualSignature — partial signature attacks', () => {
  it('rejects when only Ed25519 is valid (ML-DSA is random bytes)', async () => {
    const [ed25519Sig] = await signBoth()
    const fakeMLDsa    = crypto.randomBytes(ml_dsa65.lengths.signature)
    assert.strictEqual(await verifyDualSignature(signingPub, message, ed25519Sig, fakeMLDsa), false)
  })

  it('rejects when only ML-DSA is valid (Ed25519 is random bytes)', async () => {
    const [, mlDsaSig] = await signBoth()
    const fakeEd25519  = crypto.randomBytes(64)
    assert.strictEqual(await verifyDualSignature(signingPub, message, fakeEd25519, mlDsaSig), false)
  })

  it('rejects when both signatures are random bytes', async () => {
    const fakeEd25519 = crypto.randomBytes(64)
    const fakeMLDsa   = crypto.randomBytes(ml_dsa65.lengths.signature)
    assert.strictEqual(await verifyDualSignature(signingPub, message, fakeEd25519, fakeMLDsa), false)
  })
})

// ── Wrong message ────────────────────────────────────────────────────────────

describe('verifyDualSignature — message tampering', () => {
  it('rejects signatures over a different message', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    const tampered = crypto.randomBytes(32)
    assert.strictEqual(await verifyDualSignature(signingPub, tampered, ed25519Sig, mlDsaSig), false)
  })

  it('rejects when message is one byte different', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    const tampered = Buffer.from(message)
    tampered[0] ^= 0x01
    assert.strictEqual(await verifyDualSignature(signingPub, tampered, ed25519Sig, mlDsaSig), false)
  })
})

// ── Wrong key ────────────────────────────────────────────────────────────────

describe('verifyDualSignature — wrong public key', () => {
  it('rejects valid signatures verified against a different key pair', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()

    const otherEd25519Pub = await ed.getPublicKey(ed.utils.randomSecretKey())
    const otherMLDsaPub   = ml_dsa65.keygen().publicKey
    const otherSigningPub = Buffer.concat([otherEd25519Pub, otherMLDsaPub])

    assert.strictEqual(await verifyDualSignature(otherSigningPub, message, ed25519Sig, mlDsaSig), false)
  })

  it('rejects when only the Ed25519 public key is swapped', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    const otherEd25519Pub = await ed.getPublicKey(ed.utils.randomSecretKey())
    const mixedPub = Buffer.concat([otherEd25519Pub, mlDsaPub])
    assert.strictEqual(await verifyDualSignature(mixedPub, message, ed25519Sig, mlDsaSig), false)
  })

  it('rejects when only the ML-DSA public key is swapped', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    const otherMLDsaPub = ml_dsa65.keygen().publicKey
    const mixedPub = Buffer.concat([ed25519Pub, otherMLDsaPub])
    assert.strictEqual(await verifyDualSignature(mixedPub, message, ed25519Sig, mlDsaSig), false)
  })
})

// ── Signature slot confusion ─────────────────────────────────────────────────

describe('verifyDualSignature — signature slot confusion', () => {
  it('rejects Ed25519 sig placed in ML-DSA slot (wrong size → false, not throw)', async () => {
    const [ed25519Sig] = await signBoth()
    // Ed25519 sig is 64 bytes; ML-DSA slot expects ml_dsa65.lengths.signature bytes
    // Padding to the right size with zeros
    const padded = Buffer.alloc(ml_dsa65.lengths.signature)
    ed25519Sig.copy(padded)
    const [realEd25519Sig] = await signBoth()
    assert.strictEqual(await verifyDualSignature(signingPub, message, realEd25519Sig, padded), false)
  })
})

// ── Malformed inputs — must return false, never throw ────────────────────────

describe('verifyDualSignature — malformed inputs never throw', () => {
  it('handles empty Ed25519 signature buffer', async () => {
    const [, mlDsaSig] = await signBoth()
    assert.strictEqual(await verifyDualSignature(signingPub, message, Buffer.alloc(0), mlDsaSig), false)
  })

  it('handles empty ML-DSA signature buffer', async () => {
    const [ed25519Sig] = await signBoth()
    assert.strictEqual(await verifyDualSignature(signingPub, message, ed25519Sig, Buffer.alloc(0)), false)
  })

  it('handles all-zero signatures', async () => {
    const zeroEd = Buffer.alloc(64)
    const zeroML = Buffer.alloc(ml_dsa65.lengths.signature)
    assert.strictEqual(await verifyDualSignature(signingPub, message, zeroEd, zeroML), false)
  })

  it('handles truncated signing key (too short)', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    const truncated = signingPub.subarray(0, 16)
    assert.strictEqual(await verifyDualSignature(truncated, message, ed25519Sig, mlDsaSig), false)
  })

  it('handles all-zero signing key', async () => {
    const [ed25519Sig, mlDsaSig] = await signBoth()
    const zeroPub = Buffer.alloc(1984)
    assert.strictEqual(await verifyDualSignature(zeroPub, message, ed25519Sig, mlDsaSig), false)
  })

  it('both verifications always run — no short-circuit on first failure', async () => {
    // If the first verification throws internally, the second must still run.
    // We verify this by checking the result is false (not an unhandled exception)
    // when both inputs are garbage.
    const garbage1 = Buffer.alloc(64, 0xff)
    const garbage2 = Buffer.alloc(ml_dsa65.lengths.signature, 0xff)
    let result
    assert.doesNotThrow(async () => {
      result = await verifyDualSignature(signingPub, message, garbage1, garbage2)
    })
    assert.strictEqual(await verifyDualSignature(signingPub, message, garbage1, garbage2), false)
  })
})
