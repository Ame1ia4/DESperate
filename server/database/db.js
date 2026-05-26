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

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT ?? DB_DEFAULT_PORT),
  user:     process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  max:                              POOL_MAX_CONNECTIONS,
  idleTimeoutMillis:                POOL_IDLE_TIMEOUT_MS,
  connectionTimeoutMillis:          POOL_CONNECTION_TIMEOUT_MS,
  statement_timeout:                POOL_STATEMENT_TIMEOUT_MS,
  query_timeout:                    POOL_QUERY_TIMEOUT_MS,
  idle_in_transaction_session_timeout: POOL_IDLE_TRANSACTION_TIMEOUT_MS,
  ssl: false  // same-VM deployment, Postgres not network-exposed
})

// Verify on startup — fail fast if DB is unreachable
pool.connect((err, client, release) => {
  if (err) {
    console.error('Database connection failed — check DB_* env vars and network')
    if (process.env.NODE_ENV !== 'production') console.error(err)
    process.exit(1)
  }
  console.log('Database connected')
  release()
})

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
    await client.query('ROLLBACK')
    if (process.env.NODE_ENV !== 'production') console.error(err)
    const safe = new Error('Transaction failed')
    safe.cause = err
    throw safe
  } finally {
    client.release()
  }
}