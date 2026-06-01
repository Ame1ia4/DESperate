// 24-hour session window — enough for a user session without forcing re-login.
const SESSION_KEY_TTL_MS = 24 * 60 * 60 * 1000

const keys = new Map()

setInterval(() => {
  const now = Date.now()
  for (const [id, entry] of keys)
    if (entry.expiresAt <= now) keys.delete(id)
}, 60_000).unref()

export function storeSessionKey(deviceId, keyHex) {
  keys.set(deviceId, { keyHex, expiresAt: Date.now() + SESSION_KEY_TTL_MS })
}

// Non-consuming lookup — returns the key without deleting it.
// The session remains valid for the full TTL so a single login supports
// many API calls without forcing re-authentication.
export function getSessionKey(deviceId) {
  const entry = keys.get(deviceId)
  if (!entry || entry.expiresAt <= Date.now()) {
    keys.delete(deviceId)
    return null
  }
  return entry.keyHex
}

// Kept for backward compat with any import that uses the old name.
export { getSessionKey as consumeSessionKey }
