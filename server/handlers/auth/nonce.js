import { randomBytes } from 'node:crypto'

const NONCE_TTL_MS = 5 * 60 * 1000  // 5 minutes
const pending = new Map()

// Purge expired nonces every minute — .unref() so this timer never prevents process exit
setInterval(() => {
  const now = Date.now()
  for (const [nonce, { expires }] of pending) {
    if (expires < now) pending.delete(nonce)
  }
}, 60_000).unref()

export function issueNonce() {
  const nonce = randomBytes(32).toString('hex')
  pending.set(nonce, { expires: Date.now() + NONCE_TTL_MS })
  return nonce
}

// Single-use: deletes the entry whether valid or not so a bad nonce can't be retried.
export function consumeNonce(nonce) {
  const entry = pending.get(nonce)
  pending.delete(nonce)
  if (!entry || entry.expires < Date.now()) return false
  return true
}

export async function registrationNonce(_req, res) {
  res.json({ nonce: issueNonce() })
}
