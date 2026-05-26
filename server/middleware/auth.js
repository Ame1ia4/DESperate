import { getSession, refreshSession } from '../sessions.js'

export function requireAuth(req, res, next) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorised' })
  }
  const token = header.slice(7)
  const session = getSession(token)
  if (!session) {
    return res.status(401).json({ error: 'Unauthorised' })
  }
  refreshSession(token)
  req.deviceId    = session.deviceId
  req.userId      = session.userId
  req.sessionToken = token
  next()
}
