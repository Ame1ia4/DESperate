import pg from 'pg'
import 'dotenv/config'

const { Pool } = pg

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT ?? '5432', 10),
  user:     process.env.MERKLE_DB_USER,
  password: process.env.MERKLE_DB_PASS,
  database: process.env.DB_NAME,
  ssl:      process.env.DB_SSL?.toLowerCase() === 'false' ? false : undefined,
})

export const query = (text, params) => pool.query(text, params)

export async function withTransaction(fn) {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (err) {
    try { await client.query('ROLLBACK') } catch (_) {}
    const safe = new Error('Transaction failed')
    safe.cause = err
    throw safe
  } finally {
    client.release()
  }
}
