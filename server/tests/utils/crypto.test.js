import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from 'node:crypto'
import { verifyDualSignature } from '../../utils/crypto.js'
import { ED25519_PUB_BYTES, ED25519_SIG_BYTES, MLDSA_SIG_BYTES } from '../../constants/auth.js'

let ed25519PrivKey, ed25519PubKey, mlDsaSecKey, mlDsaPubKey
let signingPub, message, ed25519Sig, mlDsaSig

before(() => {
  ed25519PrivKey = randomBytes(32)
  ed25519PubKey  = Buffer.from(ed25519.getPublicKey(ed25519PrivKey))

  const seed = randomBytes(32)
  const keys = ml_dsa65.keygen(seed)
  mlDsaSecKey = keys.secretKey
  mlDsaPubKey = Buffer.from(keys.publicKey)

  signingPub = Buffer.concat([ed25519PubKey, mlDsaPubKey])
  message    = randomBytes(32)

  ed25519Sig = Buffer.from(ed25519.sign(message, ed25519PrivKey))
  mlDsaSig   = Buffer.from(ml_dsa65.sign(message, mlDsaSecKey))
})

describe('verifyDualSignature', () => {
  describe('happy path', () => {
    it('returns true when both signatures are valid', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, ed25519Sig, mlDsaSig), true)
    })
  })

  describe('signature forgery attacks', () => {
    it('returns false when ed25519 sig is all zeros (valid length)', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, Buffer.alloc(ED25519_SIG_BYTES), mlDsaSig), false)
    })

    it('returns false when ml_dsa sig is all zeros (valid length)', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, ed25519Sig, Buffer.alloc(MLDSA_SIG_BYTES)), false)
    })

    it('returns false when both sigs are all zeros', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, Buffer.alloc(ED25519_SIG_BYTES), Buffer.alloc(MLDSA_SIG_BYTES)), false)
    })

    it('returns false when both sigs are random bytes', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, randomBytes(ED25519_SIG_BYTES), randomBytes(MLDSA_SIG_BYTES)), false)
    })

    it('returns false when ed25519 sig is valid but ml_dsa sig is random', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, ed25519Sig, randomBytes(MLDSA_SIG_BYTES)), false)
    })

    it('returns false when ml_dsa sig is valid but ed25519 sig is random', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, randomBytes(ED25519_SIG_BYTES), mlDsaSig), false)
    })
  })

  describe('wrong message attacks', () => {
    it('returns false when message is one byte different', () => {
      const tampered = Buffer.from(message)
      tampered[0] ^= 0x01
      assert.strictEqual(verifyDualSignature(signingPub, tampered, ed25519Sig, mlDsaSig), false)
    })

    it('returns false when message is a completely different value', () => {
      assert.strictEqual(verifyDualSignature(signingPub, randomBytes(32), ed25519Sig, mlDsaSig), false)
    })

    it('returns false when message is empty', () => {
      const emptyEd = Buffer.from(ed25519.sign(Buffer.alloc(0), ed25519PrivKey))
      const emptyMl = Buffer.from(ml_dsa65.sign(Buffer.alloc(0), mlDsaSecKey))
      assert.strictEqual(verifyDualSignature(signingPub, message, emptyEd, emptyMl), false)
    })
  })

  describe('wrong key attacks', () => {
    it('returns false when signingPub is a different random key', () => {
      const otherPriv = randomBytes(32)
      const otherEd25519Pub = Buffer.from(ed25519.getPublicKey(otherPriv))
      const { publicKey: otherMlDsaPub } = ml_dsa65.keygen(randomBytes(32))
      const otherSigningPub = Buffer.concat([otherEd25519Pub, Buffer.from(otherMlDsaPub)])
      assert.strictEqual(verifyDualSignature(otherSigningPub, message, ed25519Sig, mlDsaSig), false)
    })

    it('returns false when ed25519 and ml_dsa halves of signingPub are swapped', () => {
      const swapped = Buffer.concat([mlDsaPubKey.subarray(0, ED25519_PUB_BYTES), ed25519PubKey, mlDsaPubKey.subarray(ED25519_PUB_BYTES)])
      assert.strictEqual(verifyDualSignature(swapped, message, ed25519Sig, mlDsaSig), false)
    })
  })

  describe('malformed input — must not throw', () => {
    it('returns false for truncated ed25519 sig (31 bytes)', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, ed25519Sig.subarray(0, 31), mlDsaSig), false)
    })

    it('returns false for truncated ml_dsa sig (100 bytes)', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, ed25519Sig, mlDsaSig.subarray(0, 100)), false)
    })

    it('returns false for empty ed25519 sig buffer', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, Buffer.alloc(0), mlDsaSig), false)
    })

    it('returns false for empty ml_dsa sig buffer', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, ed25519Sig, Buffer.alloc(0)), false)
    })

    it('returns false for both empty sig buffers', () => {
      assert.strictEqual(verifyDualSignature(signingPub, message, Buffer.alloc(0), Buffer.alloc(0)), false)
    })
  })

  describe('no-short-circuit invariant', () => {
    it('both algorithms evaluated — zero sigs of correct length return false without throwing', () => {
      const badEd = Buffer.alloc(ED25519_SIG_BYTES)
      const badMl = Buffer.alloc(MLDSA_SIG_BYTES)
      assert.strictEqual(verifyDualSignature(signingPub, message, badEd, badMl), false)
    })

    it('never throws regardless of malformed input combinations', () => {
      const inputs = [
        [Buffer.alloc(0), Buffer.alloc(0)],
        [Buffer.alloc(1), Buffer.alloc(1)],
        [randomBytes(ED25519_SIG_BYTES), Buffer.alloc(0)],
        [Buffer.alloc(0), randomBytes(MLDSA_SIG_BYTES)],
      ]
      for (const [eSig, mSig] of inputs) {
        assert.doesNotThrow(() => verifyDualSignature(signingPub, message, eSig, mSig))
      }
    })
  })
})
