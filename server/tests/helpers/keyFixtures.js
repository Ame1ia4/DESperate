import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from 'node:crypto'

/**
 * Generates a complete, cryptographically valid device key bundle for testing.
 * Uses real keypairs — do not call per-test; call once in beforeAll.
 */
export function generateKeyBundle() {
  const ed25519PrivKey = randomBytes(32)
  const ed25519PubKey  = ed25519.getPublicKey(ed25519PrivKey)

  const mlDsaSeed = randomBytes(32)
  const { secretKey: mlDsaSecKey, publicKey: mlDsaPubKey } = ml_dsa87.keygen(mlDsaSeed)

  const signingPub    = Buffer.concat([Buffer.from(ed25519PubKey), Buffer.from(mlDsaPubKey)])
  const signingPubHex = signingPub.toString('hex')

  const idkClassicalPub    = randomBytes(32)
  const idkClassicalPubHex = idkClassicalPub.toString('hex')

  const signedPrekeyPub    = randomBytes(32)
  const signedPrekeyPubHex = signedPrekeyPub.toString('hex')

  const spkEd25519Sig = ed25519.sign(signedPrekeyPub, ed25519PrivKey)
  const spkMlDsaSig   = ml_dsa87.sign(signedPrekeyPub, mlDsaSecKey)
  const signedPrekeySig    = Buffer.concat([Buffer.from(spkEd25519Sig), Buffer.from(spkMlDsaSig)])
  const signedPrekeySigHex = signedPrekeySig.toString('hex')

  return {
    ed25519PrivKey,
    ed25519PubKey: Buffer.from(ed25519PubKey),
    mlDsaSecKey,
    mlDsaPubKey: Buffer.from(mlDsaPubKey),
    signingPubHex,
    idkClassicalPubHex,
    signedPrekeyPub,
    signedPrekeyPubHex,
    signedPrekeySigHex,
  }
}

/** Returns the minimal valid device body for POST /auth/register */
export function validDeviceBody(bundle) {
  return {
    idk_classical_pub:       bundle.idkClassicalPubHex,
    identity_signing_pub:    bundle.signingPubHex,
    signed_prekey_pub:       bundle.signedPrekeyPubHex,
    signed_prekey_signature: bundle.signedPrekeySigHex,
  }
}

/** Produces a hex string of `n` zero bytes — valid length, invalid crypto */
export function zeroHex(n) {
  return Buffer.alloc(n).toString('hex')
}

/** Produces a hex string of `n` random bytes — valid length, invalid crypto */
export function randomHex(n) {
  return randomBytes(n).toString('hex')
}
