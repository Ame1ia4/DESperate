// session_keys.js — SRP session key store with DB persistence.
//
// The in-process Map is the primary read path (fast, no DB round-trip).
// On every storeSessionKey the key is also written to device_sessions so a
// server restart does not force every connected user to re-authenticate.
// getSessionKey falls back to the DB when the Map is cold (post-restart).
//
// Both storeSessionKey and getSessionKey are async so callers must await them.

import { query } from '../database/db.js'

const SESSION_KEY_TTL_MS = 24 * 60 * 60 * 1000   // 24 hours

const _cache = new Map()

// Evict expired entries from the in-process cache every minute.
setInterval(() => {
  const now = Date.now()
  for (const [id, entry] of _cache)
    if (entry.expiresAt <= now) _cache.delete(id)
}, 60_000).unref()

export async function storeSessionKey(deviceId, keyHex) {
  const expiresAt = Date.now() + SESSION_KEY_TTL_MS
  _cache.set(deviceId, { keyHex, expiresAt })

  // Persist to DB so the key survives a server restart.
  await query(
    `INSERT INTO device_sessions (device_id, session_key_hex, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '24 hours')
     ON CONFLICT (device_id)
     DO UPDATE SET
       session_key_hex = EXCLUDED.session_key_hex,
       expires_at      = EXCLUDED.expires_at`,
    [deviceId, keyHex]
  )
}

export async function getSessionKey(deviceId) {
  // Fast path — in-process cache.
  const cached = _cache.get(deviceId)
  if (cached) {
    if (cached.expiresAt <= Date.now()) {
      _cache.delete(deviceId)
    } else {
      return cached.keyHex
    }
  }

  // Fallback — DB lookup (handles post-restart cold cache).
  const { rows } = await query(
    `SELECT session_key_hex
     FROM   device_sessions
     WHERE  device_id  = $1
       AND  expires_at > NOW()`,
    [deviceId]
  )
  if (!rows.length) return null

  const { session_key_hex } = rows[0]
  // Repopulate cache so subsequent requests skip the DB.
  _cache.set(deviceId, { keyHex: session_key_hex, expiresAt: Date.now() + SESSION_KEY_TTL_MS })
  return session_key_hex
}

// Instantly invalidate a device's session: clear the in-process cache AND the
// durable row so the bearer token is dead on the device's very next request.
export async function revokeSessionKey(deviceId) {
  _cache.delete(deviceId)
  await query('DELETE FROM device_sessions WHERE device_id = $1', [deviceId])
}

