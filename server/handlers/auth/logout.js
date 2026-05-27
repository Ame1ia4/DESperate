import { deleteSession, deleteAllSessionsForDevice } from '../../sessions.js'

// Invalidates the current session token.
export async function logout(req, res) {
  deleteSession(req.sessionToken)
  return res.json({ message: 'Logged out' })
}

// Invalidates all sessions for this device (e.g. stolen token recovery).
export async function logoutAll(req, res) {
  deleteAllSessionsForDevice(req.deviceId)
  return res.json({ message: 'Logged out' })
}
