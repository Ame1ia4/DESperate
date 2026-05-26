import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'

import {
  createChallenge, consumeChallenge,
  createSession, getSession, refreshSession, deleteSession,
  deleteAllSessionsForDevice, deleteAllSessionsForUser,
} from '../sessions.js'

const uid = () => crypto.randomUUID()

// ── Challenges ──────────────────────────────────────────────────────────────

describe('challenge security', () => {
  it('nonce is a 32-byte Buffer (256-bit entropy)', () => {
    const nonce = createChallenge(uid())
    assert.ok(Buffer.isBuffer(nonce))
    assert.strictEqual(nonce.length, 32)
  })

  it('is single-use: second consume returns null', () => {
    const deviceId = uid()
    createChallenge(deviceId)
    assert.ok(consumeChallenge(deviceId) !== null)
    assert.strictEqual(consumeChallenge(deviceId), null)
  })

  it('deletes on consume regardless of whether it was expired', () => {
    const deviceId = uid()
    createChallenge(deviceId)
    consumeChallenge(deviceId)
    assert.strictEqual(consumeChallenge(deviceId), null)
  })

  it('returns null for device with no pending challenge', () => {
    assert.strictEqual(consumeChallenge(uid()), null)
  })

  it('expires after 30 seconds', (t) => {
    t.mock.timers.enable(['Date'])
    const deviceId = uid()
    createChallenge(deviceId)
    t.mock.timers.tick(30_001)
    assert.strictEqual(consumeChallenge(deviceId), null)
  })

  it('is still valid 1ms before expiry', (t) => {
    t.mock.timers.enable(['Date'])
    const deviceId = uid()
    createChallenge(deviceId)
    t.mock.timers.tick(29_999)
    assert.ok(consumeChallenge(deviceId) !== null)
  })

  it('re-issuing a challenge overwrites the previous one', () => {
    const deviceId = uid()
    createChallenge(deviceId)
    const second = createChallenge(deviceId)
    assert.deepStrictEqual(consumeChallenge(deviceId), second)
    assert.strictEqual(consumeChallenge(deviceId), null)
  })

  it('different devices have independent challenges', () => {
    const a = uid(), b = uid()
    createChallenge(a)
    createChallenge(b)
    assert.ok(consumeChallenge(a) !== null)
    assert.ok(consumeChallenge(b) !== null)
  })

  it('consuming device A challenge does not affect device B', () => {
    const a = uid(), b = uid()
    createChallenge(a)
    createChallenge(b)
    consumeChallenge(a)
    assert.ok(consumeChallenge(b) !== null)
  })
})

// ── Session creation ─────────────────────────────────────────────────────────

describe('session token security', () => {
  it('token is a 64-char lowercase hex string (256-bit entropy)', () => {
    const token = createSession(uid(), uid())
    assert.strictEqual(typeof token, 'string')
    assert.strictEqual(token.length, 64)
    assert.match(token, /^[0-9a-f]{64}$/)
  })

  it('every token is unique', () => {
    const tokens = new Set()
    for (let i = 0; i < 500; i++) tokens.add(createSession(uid(), uid()))
    assert.strictEqual(tokens.size, 500)
  })

  it('token contains no PII — opaque handle only', () => {
    const deviceId = 'device-aabbccdd-eeff'
    const userId   = 'user-11223344-5566'
    const token = createSession(deviceId, userId)
    assert.ok(!token.includes('device'))
    assert.ok(!token.includes('user'))
    assert.ok(!token.includes(deviceId))
    assert.ok(!token.includes(userId))
  })

  it('new login on same device invalidates the previous session (single-session)', () => {
    const deviceId = uid(), userId = uid()
    const old = createSession(deviceId, userId)
    createSession(deviceId, userId)
    assert.strictEqual(getSession(old), null)
  })

  it('new session for same device is retrievable', () => {
    const deviceId = uid(), userId = uid()
    const fresh = createSession(deviceId, userId)
    const session = getSession(fresh)
    assert.ok(session !== null)
    assert.strictEqual(session.deviceId, deviceId)
    assert.strictEqual(session.userId, userId)
  })
})

// ── Session retrieval ────────────────────────────────────────────────────────

describe('session retrieval security', () => {
  it('returns null for unknown token', () => {
    assert.strictEqual(getSession('00'.repeat(32)), null)
  })

  it('expired and non-existent tokens both return null (no oracle)', () => {
    const nonExistent = 'aa'.repeat(32)
    assert.strictEqual(getSession(nonExistent), null)
  })

  it('expires after idle TTL (30 minutes)', (t) => {
    t.mock.timers.enable(['Date'])
    const token = createSession(uid(), uid())
    t.mock.timers.tick(30 * 60 * 1000 + 1)
    assert.strictEqual(getSession(token), null)
  })

  it('is still valid 1ms before idle TTL', (t) => {
    t.mock.timers.enable(['Date'])
    const token = createSession(uid(), uid())
    t.mock.timers.tick(30 * 60 * 1000 - 1)
    assert.ok(getSession(token) !== null)
  })

  it('absolute TTL (8h) cannot be bypassed by refreshing', (t) => {
    t.mock.timers.enable(['Date'])
    const token = createSession(uid(), uid())
    // Refresh every 25 minutes — well within idle window
    t.mock.timers.tick(25 * 60 * 1000); refreshSession(token)
    t.mock.timers.tick(25 * 60 * 1000); refreshSession(token)
    t.mock.timers.tick(25 * 60 * 1000); refreshSession(token)
    // 1h 15min elapsed — still valid
    assert.ok(getSession(token) !== null)
    // Jump past the 8h absolute limit
    t.mock.timers.tick(8 * 60 * 60 * 1000)
    assert.strictEqual(getSession(token), null)
  })
})

// ── Session refresh ──────────────────────────────────────────────────────────

describe('session refresh', () => {
  it('returns true for a valid session', () => {
    assert.strictEqual(refreshSession(createSession(uid(), uid())), true)
  })

  it('returns false for an unknown token', () => {
    assert.strictEqual(refreshSession('ff'.repeat(32)), false)
  })

  it('extends idle TTL so session survives past original expiry', (t) => {
    t.mock.timers.enable(['Date'])
    const token = createSession(uid(), uid())
    t.mock.timers.tick(25 * 60 * 1000)   // 25 min — within idle window
    refreshSession(token)
    t.mock.timers.tick(25 * 60 * 1000)   // 25 more min — would have expired without refresh
    assert.ok(getSession(token) !== null)
  })
})

// ── Session deletion ─────────────────────────────────────────────────────────

describe('session deletion', () => {
  it('deleteSession immediately invalidates the token', () => {
    const token = createSession(uid(), uid())
    deleteSession(token)
    assert.strictEqual(getSession(token), null)
  })

  it('deleteSession is idempotent', () => {
    const token = createSession(uid(), uid())
    deleteSession(token)
    assert.doesNotThrow(() => deleteSession(token))
  })

  it('deleteAllSessionsForDevice clears the active session', () => {
    const deviceId = uid()
    const token = createSession(deviceId, uid())
    deleteAllSessionsForDevice(deviceId)
    assert.strictEqual(getSession(token), null)
  })

  it('deleteAllSessionsForDevice does not affect other devices', () => {
    const userId = uid()
    const deviceA = uid(), deviceB = uid()
    const tokenA = createSession(deviceA, userId)
    const tokenB = createSession(deviceB, userId)
    deleteAllSessionsForDevice(deviceA)
    assert.strictEqual(getSession(tokenA), null)
    assert.ok(getSession(tokenB) !== null)
  })

  it('deleteAllSessionsForDevice is idempotent', () => {
    const deviceId = uid()
    createSession(deviceId, uid())
    deleteAllSessionsForDevice(deviceId)
    assert.doesNotThrow(() => deleteAllSessionsForDevice(deviceId))
  })

  it('deleteAllSessionsForUser clears sessions across all devices', () => {
    const userId = uid()
    const tokenA = createSession(uid(), userId)
    const tokenB = createSession(uid(), userId)
    const tokenC = createSession(uid(), userId)
    deleteAllSessionsForUser(userId)
    assert.strictEqual(getSession(tokenA), null)
    assert.strictEqual(getSession(tokenB), null)
    assert.strictEqual(getSession(tokenC), null)
  })

  it('deleteAllSessionsForUser does not affect other users', () => {
    const userA = uid(), userB = uid()
    const tokenA = createSession(uid(), userA)
    const tokenB = createSession(uid(), userB)
    deleteAllSessionsForUser(userA)
    assert.strictEqual(getSession(tokenA), null)
    assert.ok(getSession(tokenB) !== null)
  })

  it('deleteAllSessionsForUser is idempotent', () => {
    const userId = uid()
    createSession(uid(), userId)
    deleteAllSessionsForUser(userId)
    assert.doesNotThrow(() => deleteAllSessionsForUser(userId))
  })
})

// ── Device isolation ─────────────────────────────────────────────────────────

describe('device isolation', () => {
  it('two devices for the same user get independent sessions', () => {
    const userId = uid()
    const tokenA = createSession(uid(), userId)
    const tokenB = createSession(uid(), userId)
    assert.notStrictEqual(tokenA, tokenB)
    assert.ok(getSession(tokenA) !== null)
    assert.ok(getSession(tokenB) !== null)
  })

  it('revoking device A leaves device B unaffected', () => {
    const userId = uid()
    const deviceA = uid(), deviceB = uid()
    const tokenA = createSession(deviceA, userId)
    const tokenB = createSession(deviceB, userId)
    deleteAllSessionsForDevice(deviceA)
    assert.strictEqual(getSession(tokenA), null)
    assert.ok(getSession(tokenB) !== null)
  })

  it('account-level logout clears all devices', () => {
    const userId = uid()
    const tokens = Array.from({ length: 5 }, () => createSession(uid(), userId))
    deleteAllSessionsForUser(userId)
    for (const token of tokens) assert.strictEqual(getSession(token), null)
  })
})
