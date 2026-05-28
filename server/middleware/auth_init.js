import * as srp from 'secure-remote-password/server'
import { createHmac } from 'node:crypto'
import { query, withTransaction } from '../database/db.js'

//unknown users get a deterministic fake salt and verifier, so attackers can't distinguish missing users from real ones based on timing or retries. The fake
//verifier is keyed to the server secret so it looks like a valid SRP verifier.
const SERVER_SECRET = process.env.AUTH_FAKE_SECRET

// Deterministic HMAC-keyed fake salt for unknown usernames.
// Same username → same salt across requests, so timing/repeat probing
// can't distinguish a missing user from a real one.
// Keyed to AUTH_SECRET so attackers can't pre-compute the mapping.
function fakeSalt(username) {
  return createHmac('sha256', SERVER_SECRET).update(username).digest('hex')
}

export async function authInit(req, res) {
  const { username, clientPublicEphemeral } = req.body

  if (!username || !clientPublicEphemeral ||
      typeof username !== 'string' || typeof clientPublicEphemeral !== 'string') {
    return res.status(400).json({ error: 'Invalid request' })
  }

  const result = await query(
    'SELECT id, srp_salt, srp_verifier FROM users WHERE username = $1',
    [username]
  )
  const user = result.rows[0]

  if (!user) {
    // Return a structurally valid but unverifiable challenge.
    // The dummy verifier is keyed to the server secret so the ephemeral B
    // value looks legitimate without leaking anything useful.
    const salt = fakeSalt(username)
    const dummyVerifier = fakeSalt(username + ':verifier')
    const ephemeral = srp.generateEphemeral(dummyVerifier)
    return res.json({ salt, serverPublicEphemeral: ephemeral.public })
  }

  const serverEphemeral = srp.generateEphemeral(user.srp_verifier)

  // Atomically replace any existing challenge for this user.
  // Prevents challenge accumulation and ensures a retried client
  // always gets a fresh handshake.
  await withTransaction(async (client) => {
    await client.query(
      'DELETE FROM srp_challenges WHERE user_id = $1',
      [user.id]
    )
    // Only the secret is stored — the public half (B) goes to the client
    // and is discarded here. A is re-sent by the client in round 2.
    await client.query(
      'INSERT INTO srp_challenges (user_id, srp_server_secret) VALUES ($1, $2)',
      [user.id, serverEphemeral.secret]
    )
  })

  res.json({
    salt: user.srp_salt,
    serverPublicEphemeral: serverEphemeral.public,
  })
}
