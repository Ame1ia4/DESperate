import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ED25519_PUB_BYTES } from '../constants/auth.js'

// Verifies Ed25519 + ML-DSA-87 dual signatures over the same message.
// signingPub is the concatenation [ed25519_pub || ml_dsa_pub].
// Both signatures are always evaluated — no short-circuit — to prevent timing oracles.
export function verifyDualSignature(signingPub, message, ed25519Sig, mlDsaSig) {
  const ed25519Pub = signingPub.subarray(0, ED25519_PUB_BYTES)
  const mlDsaPub   = signingPub.subarray(ED25519_PUB_BYTES)

  let ed25519Ok = false
  let mlDsaOk   = false

  try {
    ed25519Ok = ed25519.verify(ed25519Sig, message, ed25519Pub)
  } catch {
    ed25519Ok = false
  }

  try {
    mlDsaOk = ml_dsa87.verify(mlDsaSig, message, mlDsaPub)
  } catch {
    mlDsaOk = false
  }

  return ed25519Ok && mlDsaOk
}
