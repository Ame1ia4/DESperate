import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa'

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m))

const ED25519_PUB_BYTES = 32

// Verify dual Ed25519 + ML-DSA signatures over `message`.
// signingPub: combined 1984-byte key (Ed25519 || ML-DSA).
// Returns false on any failure — never throws.
export async function verifyDualSignature(signingPub, message, ed25519Sig, mlDsaSig) {
  let ed25519Valid = false
  let mlDsaValid   = false
  try { ed25519Valid = await ed.verify(ed25519Sig, message, signingPub.subarray(0, ED25519_PUB_BYTES)) } catch {}
  try { mlDsaValid   = ml_dsa65.verify(signingPub.subarray(ED25519_PUB_BYTES), message, mlDsaSig)      } catch {}
  return ed25519Valid && mlDsaValid
}
