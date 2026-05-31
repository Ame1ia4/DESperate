const SESSION_KEY_TTL_MS = 30_000

const keys = new Map()

setInterval(() => {
  const now = Date.now()
  for (const [id, entry] of keys)
    if (entry.expiresAt <= now) keys.delete(id)
}, 10_000).unref()

export function storeSessionKey(deviceId, keyHex) {
  keys.set(deviceId, { keyHex, expiresAt: Date.now() + SESSION_KEY_TTL_MS })
}

// One-use: deletes entry on read, whether valid or expired.
export function consumeSessionKey(deviceId) {
  const entry = keys.get(deviceId)
  keys.delete(deviceId)
  if (!entry || entry.expiresAt <= Date.now()) return null
  return entry.keyHex
}
