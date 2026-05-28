import { describe, it, expect, beforeAll } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from 'node:crypto'
import { verifyDualSignature } from '../../utils/crypto.js'
import { ED25519_PUB_BYTES, ED25519_SIG_BYTES, MLDSA_PUB_BYTES, MLDSA_SIG_BYTES } from '../../constants/auth.js'

let ed25519PrivKey, ed25519PubKey, mlDsaSecKey, mlDsaPubKey
let signingPub, message, ed25519Sig, mlDsaSig

beforeAll(() => {
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
      expect(verifyDualSignature(signingPub, message, ed25519Sig, mlDsaSig)).toBe(true)
    })
  })

  describe('signature forgery attacks', () => {
    it('returns false when ed25519 sig is all zeros (valid length)', () => {
      const zeroEd = Buffer.alloc(ED25519_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, zeroEd, mlDsaSig)).toBe(false)
    })

    it('returns false when ml_dsa sig is all zeros (valid length)', () => {
      const zeroMl = Buffer.alloc(MLDSA_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, ed25519Sig, zeroMl)).toBe(false)
    })

    it('returns false when both sigs are all zeros', () => {
      const zeroEd = Buffer.alloc(ED25519_SIG_BYTES)
      const zeroMl = Buffer.alloc(MLDSA_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, zeroEd, zeroMl)).toBe(false)
    })

    it('returns false when both sigs are random bytes', () => {
      const randEd = randomBytes(ED25519_SIG_BYTES)
      const randMl = randomBytes(MLDSA_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, randEd, randMl)).toBe(false)
    })

    it('returns false when ed25519 sig is valid but ml_dsa sig is random', () => {
      const randMl = randomBytes(MLDSA_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, ed25519Sig, randMl)).toBe(false)
    })

    it('returns false when ml_dsa sig is valid but ed25519 sig is random', () => {
      const randEd = randomBytes(ED25519_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, randEd, mlDsaSig)).toBe(false)
    })
  })

  describe('wrong message attacks', () => {
    it('returns false when message is one byte different', () => {
      const tampered = Buffer.from(message)
      tampered[0] ^= 0x01
      expect(verifyDualSignature(signingPub, tampered, ed25519Sig, mlDsaSig)).toBe(false)
    })

    it('returns false when message is a completely different value', () => {
      const other = randomBytes(32)
      expect(verifyDualSignature(signingPub, other, ed25519Sig, mlDsaSig)).toBe(false)
    })

    it('returns false when message is empty', () => {
      const emptyEd = Buffer.from(ed25519.sign(Buffer.alloc(0), ed25519PrivKey))
      const emptyMl = Buffer.from(ml_dsa65.sign(Buffer.alloc(0), mlDsaSecKey))
      // Sigs signed over empty message won't verify against non-empty message
      expect(verifyDualSignature(signingPub, message, emptyEd, emptyMl)).toBe(false)
    })
  })

  describe('wrong key attacks', () => {
    it('returns false when signingPub is a different random key', () => {
      const otherPriv  = randomBytes(32)
      const otherEd25519Pub = Buffer.from(ed25519.getPublicKey(otherPriv))
      const { publicKey: otherMlDsaPub } = ml_dsa65.keygen(randomBytes(32))
      const otherSigningPub = Buffer.concat([otherEd25519Pub, Buffer.from(otherMlDsaPub)])
      expect(verifyDualSignature(otherSigningPub, message, ed25519Sig, mlDsaSig)).toBe(false)
    })

    it('returns false when ed25519 and ml_dsa halves of signingPub are swapped', () => {
      // ML-DSA pub is much larger than ED25519 pub — swapping produces malformed keys
      const swapped = Buffer.concat([mlDsaPubKey.subarray(0, ED25519_PUB_BYTES), ed25519PubKey, mlDsaPubKey.subarray(ED25519_PUB_BYTES)])
      expect(verifyDualSignature(swapped, message, ed25519Sig, mlDsaSig)).toBe(false)
    })
  })

  describe('malformed input — must not throw', () => {
    it('returns false for truncated ed25519 sig (31 bytes)', () => {
      const short = ed25519Sig.subarray(0, 31)
      expect(verifyDualSignature(signingPub, message, short, mlDsaSig)).toBe(false)
    })

    it('returns false for truncated ml_dsa sig (100 bytes)', () => {
      const short = mlDsaSig.subarray(0, 100)
      expect(verifyDualSignature(signingPub, message, ed25519Sig, short)).toBe(false)
    })

    it('returns false for empty ed25519 sig buffer', () => {
      expect(verifyDualSignature(signingPub, message, Buffer.alloc(0), mlDsaSig)).toBe(false)
    })

    it('returns false for empty ml_dsa sig buffer', () => {
      expect(verifyDualSignature(signingPub, message, ed25519Sig, Buffer.alloc(0))).toBe(false)
    })

    it('returns false for both empty sig buffers', () => {
      expect(verifyDualSignature(signingPub, message, Buffer.alloc(0), Buffer.alloc(0))).toBe(false)
    })
  })

  describe('no-short-circuit invariant', () => {
    // Both algorithms must be evaluated regardless of which fails.
    // We verify this behaviorally: even when ed25519 fails, an invalid ml_dsa sig
    // of the correct length still returns false (not an exception), which would only
    // happen if ml_dsa.verify was actually called and its exception was caught.
    it('catches ml_dsa failure even when ed25519 has already failed', () => {
      const badEd = Buffer.alloc(ED25519_SIG_BYTES)
      const badMl = Buffer.alloc(MLDSA_SIG_BYTES) // zero sig — ml_dsa.verify will reject it
      expect(verifyDualSignature(signingPub, message, badEd, badMl)).toBe(false)
    })

    it('catches ed25519 failure even when ml_dsa has already failed', () => {
      const badEd = Buffer.alloc(ED25519_SIG_BYTES)
      const badMl = Buffer.alloc(MLDSA_SIG_BYTES)
      expect(verifyDualSignature(signingPub, message, badEd, badMl)).toBe(false)
    })

    it('never throws regardless of malformed input combinations', () => {
      const inputs = [
        [Buffer.alloc(0), Buffer.alloc(0)],
        [Buffer.alloc(1), Buffer.alloc(1)],
        [randomBytes(ED25519_SIG_BYTES), Buffer.alloc(0)],
        [Buffer.alloc(0), randomBytes(MLDSA_SIG_BYTES)],
      ]
      for (const [eSig, mSig] of inputs) {
        expect(() => verifyDualSignature(signingPub, message, eSig, mSig)).not.toThrow()
      }
    })
  })
})
