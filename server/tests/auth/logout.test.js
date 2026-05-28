import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'

vi.mock('../../sessions.js', () => ({
  deleteSession:              vi.fn(),
  deleteAllSessionsForDevice: vi.fn(),
  createSession:              vi.fn(),
}))

import * as sessions from '../../sessions.js'
import { logout, logoutAll } from '../../handlers/auth/logout.js'

function createApp(sessionToken = 'test-token', deviceId = 'test-device-id') {
  const app = express()
  app.use(express.json())
  // Inject session context the way auth middleware would
  app.use((req, _res, next) => {
    req.sessionToken = sessionToken
    req.deviceId     = deviceId
    next()
  })
  app.post('/auth/logout',     logout)
  app.post('/auth/logout-all', logoutAll)
  app.use((err, _req, res, _next) => res.status(500).json({ error: 'Internal server error' }))
  return app
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('POST /auth/logout', () => {
  it('returns 200 with logged-out message', async () => {
    const res = await request(createApp()).post('/auth/logout').send()
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ message: 'Logged out' })
  })

  it('calls deleteSession with the current session token', async () => {
    await request(createApp('my-token', 'dev-id')).post('/auth/logout').send()
    expect(sessions.deleteSession).toHaveBeenCalledWith('my-token')
    expect(sessions.deleteSession).toHaveBeenCalledOnce()
  })

  it('does NOT call deleteAllSessionsForDevice', async () => {
    await request(createApp()).post('/auth/logout').send()
    expect(sessions.deleteAllSessionsForDevice).not.toHaveBeenCalled()
  })

  it('is idempotent — returns 200 even if session was already invalid', async () => {
    // deleteSession is fire-and-forget; no error expected
    sessions.deleteSession.mockImplementation(() => {})
    const res = await request(createApp()).post('/auth/logout').send()
    expect(res.status).toBe(200)
  })
})

describe('POST /auth/logout-all', () => {
  it('returns 200 with logged-out message', async () => {
    const res = await request(createApp()).post('/auth/logout-all').send()
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ message: 'Logged out' })
  })

  it('calls deleteAllSessionsForDevice with the device ID', async () => {
    await request(createApp('my-token', 'my-device')).post('/auth/logout-all').send()
    expect(sessions.deleteAllSessionsForDevice).toHaveBeenCalledWith('my-device')
    expect(sessions.deleteAllSessionsForDevice).toHaveBeenCalledOnce()
  })

  it('does NOT call deleteSession', async () => {
    await request(createApp()).post('/auth/logout-all').send()
    expect(sessions.deleteSession).not.toHaveBeenCalled()
  })

  it('is idempotent — returns 200 even if no sessions exist for device', async () => {
    sessions.deleteAllSessionsForDevice.mockImplementation(() => {})
    const res = await request(createApp()).post('/auth/logout-all').send()
    expect(res.status).toBe(200)
  })

  it('logout and logout-all return identical JSON bodies', async () => {
    const resLogout    = await request(createApp()).post('/auth/logout').send()
    const resLogoutAll = await request(createApp()).post('/auth/logout-all').send()
    expect(resLogout.body).toEqual(resLogoutAll.body)
  })
})
