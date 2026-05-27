import crypto from 'node:crypto'

const NONCE_BYTES                  = 32
const TOKEN_BYTES                  = 32
const CHALLENGE_TTL_MS             = 30_000
const SESSION_IDLE_TTL_MS          = 30 * 60 * 1000
const SESSION_ABSOLUTE_TTL_MS      = 8  * 60 * 60 * 1000
const CLEANUP_INTERVAL_MS          = 5  * 60 * 1000

// { deviceId → { nonce: Buffer, expiresAt: number } }
const challenges = new Map()

// { token → { deviceId, userId, expiresAt, absoluteExpiresAt, createdAt } }
const sessions = new Map()

// Reverse indexes — keep these consistent with sessions at all times
const sessionsByDevice = new Map()  // deviceId → Set<token>
const sessionsByUser   = new Map()  // userId   → Set<deviceId>

// Remove one token from all three stores atomically (single-threaded, so truly atomic).
function _removeToken(token) {
  const session = sessions.get(token)
  if (!session) return
  const { deviceId, userId } = session

  sessions.delete(token)

  const deviceTokens = sessionsByDevice.get(deviceId)
  if (deviceTokens) {
    deviceTokens.delete(token)
    if (deviceTokens.size === 0) {
      sessionsByDevice.delete(deviceId)
      const userDevices = sessionsByUser.get(userId)
      if (userDevices) {
        userDevices.delete(deviceId)
        if (userDevices.size === 0) sessionsByUser.delete(userId)
      }
    }
  }
}

export function createChallenge(deviceId) {
  const nonce = crypto.randomBytes(NONCE_BYTES)
  challenges.set(deviceId, { nonce, expiresAt: Date.now() + CHALLENGE_TTL_MS })
  return nonce
}

export function consumeChallenge(deviceId) {
  const entry = challenges.get(deviceId)
  challenges.delete(deviceId)  // single-use: delete regardless of outcome
  if (!entry || Date.now() > entry.expiresAt) return null
  return entry.nonce
}

export function createSession(deviceId, userId) {
  // Single session per device — invalidate any existing session before creating a new one
  deleteAllSessionsForDevice(deviceId)

  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex')
  const now = Date.now()
  sessions.set(token, {
    deviceId,
    userId,
    expiresAt:         now + SESSION_IDLE_TTL_MS,
    absoluteExpiresAt: now + SESSION_ABSOLUTE_TTL_MS,
    createdAt:         now,
  })

  if (!sessionsByDevice.has(deviceId)) sessionsByDevice.set(deviceId, new Set())
  sessionsByDevice.get(deviceId).add(token)

  if (!sessionsByUser.has(userId)) sessionsByUser.set(userId, new Set())
  sessionsByUser.get(userId).add(deviceId)

  return token
}

export function getSession(token) {
  const session = sessions.get(token)
  if (!session) return null
  const now = Date.now()
  if (now > session.expiresAt || now > session.absoluteExpiresAt) {
    _removeToken(token)
    return null
  }
  return { deviceId: session.deviceId, userId: session.userId }
}

export function refreshSession(token) {
  const session = sessions.get(token)
  if (!session) return false
  const now = Date.now()
  if (now > session.expiresAt || now > session.absoluteExpiresAt) {
    _removeToken(token)
    return false
  }
  session.expiresAt = now + SESSION_IDLE_TTL_MS
  return true
}

export function deleteSession(token) {
  _removeToken(token)
}

// Revoke all sessions for one device — O(k) where k = sessions for that device
export function deleteAllSessionsForDevice(deviceId) {
  const deviceTokens = sessionsByDevice.get(deviceId)
  if (!deviceTokens) return
  for (const token of [...deviceTokens]) {
    _removeToken(token)
  }
}

// Revoke all sessions across every device for a user — for account deletion / compromise
export function deleteAllSessionsForUser(userId) {
  const userDevices = sessionsByUser.get(userId)
  if (!userDevices) return
  for (const deviceId of [...userDevices]) {
    deleteAllSessionsForDevice(deviceId)
  }
}

// Sweep both maps every 5 minutes; unref so this doesn't block graceful shutdown
setInterval(() => {
  const now = Date.now()
  for (const [deviceId, entry] of challenges) {
    if (now > entry.expiresAt) challenges.delete(deviceId)
  }
  for (const [token, session] of sessions) {
    if (now > session.expiresAt || now > session.absoluteExpiresAt) _removeToken(token)
  }
}, CLEANUP_INTERVAL_MS).unref()
