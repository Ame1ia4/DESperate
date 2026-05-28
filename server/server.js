import 'dotenv/config'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { verifyRoot } from './blockchain/verify.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

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
app.use(express.static(join(__dirname, 'blockchain')))
app.get('/', (_, res) => res.sendFile(join(__dirname, 'blockchain', 'verification.html')))
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

// ── Auth stubs (unprotected until WebAuthn/JWT is implemented) ──
app.post('/auth/register',  authLimiter, (_, res) => res.json({ message: 'register stub' }))
app.post('/auth/challenge', authLimiter, (_, res) => res.json({ message: 'challenge stub' }))
app.post('/auth/verify',    authLimiter, (_, res) => res.json({ message: 'verify stub' }))

// ── Message / key / device stubs ──
app.post('/messages',        (_, res) => res.json({ message: 'send stub' }))
app.get('/messages/pending', (_, res) => res.json({ message: 'pull stub' }))
app.post('/messages/:id/ack',(_, res) => res.json({ message: 'ack stub' }))

app.post('/keys/opks',      (_, res) => res.json({ message: 'opk upload stub' }))
app.get('/keys/:username',  (_, res) => res.json({ message: 'key fetch stub' }))

app.post('/devices/revoke', (_, res) => res.json({ message: 'revoke stub' }))

// ── 404 ──
app.use((_, res) => res.status(404).json({ error: 'Not found' }))

// ── Global error handler ──
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: 'Internal server error' })
})

app.listen(80, () => console.log('Server running on :80'))