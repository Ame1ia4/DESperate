import 'dotenv/config'
import crypto from 'crypto'
import { readFileSync } from 'fs'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { verifyRoot } from './blockchain/merkle-verify.js'
import { register, authChallenge } from './handlers/auth/index.js'
import { authInit } from './middleware/auth_init.js'
import { authVerify } from './middleware/auth_verify.js'
import { requireDeviceAuth } from './middleware/device_auth.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

const verificationHtmlTemplate = readFileSync(
  join(__dirname, 'blockchain', 'verification.html'), 'utf-8'
)

const app = express()

// Per-request nonce — must be set before Helmet reads it
app.use((_req, res, next) => {
  res.locals.nonce = crypto.randomBytes(32).toString('base64')
  next()
})

// ── Middleware ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'strict-dynamic'",
        // Helmet calls this function per request so each response gets its own nonce
        (_req, res) => `'nonce-${res.locals.nonce}'`,
        // Fallbacks for browsers without strict-dynamic — ignored by CSP3-capable browsers
        'https:',
        "'unsafe-inline'",
      ],
      styleSrc:  ["'self'", 'https://fonts.googleapis.com'],
      fontSrc:   ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:    ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri:   ["'self'"],
      formAction: ["'self'"],
    },
  },
}))
app.set('trust proxy', 1)
app.use(cors({ origin: `https://${process.env.SUBDOMAIN}` }))
app.use(express.json({ limit: '2mb' }))

const authLimiter    = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 })
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })
app.use(generalLimiter)

// ── Public routes ──
// HTML routes must come before express.static so nonces are always injected
const serveVerification = (req, res) => {
  const html = verificationHtmlTemplate.replace(/<script/g, `<script nonce="${res.locals.nonce}"`)
  res.type('html').send(html)
}
app.get('/', serveVerification)
app.get('/verification.html', serveVerification)

app.use(express.static(join(__dirname, 'blockchain')))
app.get('/health', (_, res) => res.json({ status: 'ok' }))

const HEX64_RE = /^(0x)?[0-9a-f]{64}$/i
app.get('/api/blockchain/verify', async (req, res) => {
  const { root } = req.query
  if (!root || !HEX64_RE.test(root))
    return res.status(400).json({ error: 'root must be a 64-character hex string' })
  try {
    const result = await verifyRoot(root)
    res.json(result)
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// ── Auth  ──
app.post('/auth/register', authLimiter, register)
app.post('/auth/init',     authLimiter, authInit)
app.post('/auth/verify',   authLimiter, authVerify)
app.get('/auth/challenge', authLimiter, authChallenge)

// ── Protected routes (require device challenge-response auth) ──
app.post('/messages',        requireDeviceAuth, (_, res) => res.json({ message: 'send stub' }))
app.get('/messages/pending', requireDeviceAuth, (_, res) => res.json({ message: 'pull stub' }))
app.post('/messages/:id/ack',requireDeviceAuth, (_, res) => res.json({ message: 'ack stub' }))

app.post('/keys/opks',      requireDeviceAuth, (_, res) => res.json({ message: 'opk upload stub' }))
app.get('/keys/:username',  requireDeviceAuth, (_, res) => res.json({ message: 'key fetch stub' }))

app.post('/devices/revoke', requireDeviceAuth, (_, res) => res.json({ message: 'revoke stub' }))

// ── 404 ──
app.use((_, res) => res.status(404).json({ error: 'Not found' }))

// ── Global error handler ──
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: 'Internal server error' })
})

app.listen(80, () => console.log('Server running on :80'))