import 'dotenv/config'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { requireAuth } from './middleware/auth.js'
import { register, challenge, verify, logout, logoutAll } from './handlers/auth.js'

const app = express()

// ── Middleware ──
app.use(helmet())
app.set('trust proxy', 1)
app.use(cors({ origin: `https://${process.env.SUBDOMAIN}` }))
app.use(express.json({ limit: '2mb' }))

const authLimiter    = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 })
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })
app.use(generalLimiter)

// ── Public routes ──
app.get('/', (_, res) => res.redirect('https://www.youtube.com/watch?v=ftgcwsBqS0U'))
app.get('/health', (_, res) => res.json({ status: 'ok' }))

app.post('/auth/register',  authLimiter, register)
app.post('/auth/challenge', authLimiter, challenge)
app.post('/auth/verify',    authLimiter, verify)

// ── Protected routes ──
app.post('/auth/logout',     authLimiter, requireAuth, logout)
app.post('/auth/logout-all', authLimiter, requireAuth, logoutAll)

app.post('/messages',         requireAuth, (_, res) => res.json({ message: 'send stub' }))
app.get('/messages/pending',  requireAuth, (_, res) => res.json({ message: 'pull stub' }))
app.post('/messages/:id/ack', requireAuth, (_, res) => res.json({ message: 'ack stub' }))

app.post('/keys/opks',      requireAuth, (_, res) => res.json({ message: 'opk upload stub' }))
app.get('/keys/:username',  requireAuth, (_, res) => res.json({ message: 'key fetch stub' }))

app.post('/devices/revoke', requireAuth, (_, res) => res.json({ message: 'revoke stub' }))

// ── 404 ──
app.use((_, res) => res.status(404).json({ error: 'Not found' }))

// ── Global error handler ──
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: 'Internal server error' })
})

app.listen(80, () => console.log('Server running on :80'))