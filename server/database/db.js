// db.js
import pg from 'pg'
import 'dotenv/config'

const { Pool } = pg

const DB_DEFAULT_PORT                    = 5432
const POOL_MAX_CONNECTIONS               = 10
const POOL_IDLE_TIMEOUT_MS               = 30_000
const POOL_CONNECTION_TIMEOUT_MS         = 2_000
const POOL_STATEMENT_TIMEOUT_MS          = 5_000
const POOL_QUERY_TIMEOUT_MS              = 6_000
const POOL_IDLE_TRANSACTION_TIMEOUT_MS   = 10_000

const required = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME']
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing required env var: ${key}`)
}

const rawPort = parseInt(process.env.DB_PORT ?? DB_DEFAULT_PORT, 10)
if (!Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
  throw new Error(`Invalid DB_PORT: ${process.env.DB_PORT} — must be 1–65535`)
}

// DB_SSL=false → disabled (same-VM); DB_SSL=no-verify → SSL, skip cert check;
// anything else (or omitted in production) → full SSL verification.
function resolveSSL() {
  const val = process.env.DB_SSL?.toLowerCase()
  if (val === 'false') return false
  if (val === 'no-verify') return { rejectUnauthorized: false }
  if (val === 'true' || process.env.NODE_ENV === 'production') return true
  return false
}

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     rawPort,
  user:     process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  max:                              POOL_MAX_CONNECTIONS,
  idleTimeoutMillis:                POOL_IDLE_TIMEOUT_MS,
  connectionTimeoutMillis:          POOL_CONNECTION_TIMEOUT_MS,
  statement_timeout:                POOL_STATEMENT_TIMEOUT_MS,
  query_timeout:                    POOL_QUERY_TIMEOUT_MS,
  idle_in_transaction_session_timeout: POOL_IDLE_TRANSACTION_TIMEOUT_MS,
  ssl: resolveSSL(),
})

// Verify on startup — log and continue so /health stays reachable even if DB is transiently down
pool.connect((err, client, release) => {
  if (err) {
    console.error('Database connection failed — check DB_* env vars and network', err.message)
    return
  }
  console.log('Database connected')
  release()
})

// Drain the pool on shutdown so in-flight queries finish cleanly.
// Callers should call registerShutdownSignals(httpServer) so new connections
// are refused before the pool closes — prevents 57P01 errors on live requests.
async function shutdown(signal, httpServer) {
  console.log(`${signal} received — draining`)
  await new Promise((resolve) => httpServer.close(resolve))
  await pool.end()
  process.exit(0)
}

export function registerShutdownSignals(httpServer) {
  process.once('SIGTERM', () => shutdown('SIGTERM', httpServer))
  process.once('SIGINT',  () => shutdown('SIGINT',  httpServer))
}

// Parameterised query — always use this, never string concat
export const query = (text, params) => pool.query(text, params)

// Transaction wrapper — BEGIN/COMMIT/ROLLBACK
export async function withTransaction(fn) {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (err) {
    try {
      await client.query('ROLLBACK')
    } catch (rollbackErr) {
      console.error('ROLLBACK failed', rollbackErr)
    }
    if (process.env.NODE_ENV !== 'production') console.error(err)
    const safe = new Error('Transaction failed')
    safe.cause = err
    throw safe
  } finally {
    client.release()
  }
}