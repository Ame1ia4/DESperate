// Runs before any test file via --import. Patches pg.Pool so that importing
// db.js never opens a real connection and never calls process.exit(1).
// Tests control what query/withTransaction return through globalThis.__db.

import pg from 'pg'

// Fake env vars — db.js and auth_init.js validate these at module load
process.env.AUTH_FAKE_SECRET ??= 'test-fake-secret-for-hmac-keying'
process.env.DB_HOST ??= 'test-host'
process.env.DB_PORT ??= '5432'
process.env.DB_USER ??= 'test-user'
process.env.DB_PASS ??= 'test-pass'
process.env.DB_NAME ??= 'test-db'
process.env.DB_SSL  ??= 'false'

// Shared state — tests set these before each request
globalThis.__db = {
  // fn(text, params) → { rows } — used by the exported `query`
  queryImpl: null,
  // array of { rows } (or { throwError: Error }) — consumed in order by
  // client.query() calls inside withTransaction (BEGIN/COMMIT/ROLLBACK skipped)
  clientQueryResults: [],
}

function makeFakeClient() {
  let callIndex = 0
  return {
    async query(text, params) {
      if (text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK') return {}
      const results = globalThis.__db.clientQueryResults
      const item = results[callIndex++]
      if (!item) throw new Error(`No clientQueryResults[${callIndex - 1}] set`)
      if (item.throwError) throw item.throwError
      if (typeof item.onCall === 'function') item.onCall(text, params)
      return item
    },
    release() {},
  }
}

pg.Pool = class FakePool {
  constructor() {}

  connect(callback) {
    // db.js calls this at startup with a callback — succeed silently
    if (typeof callback === 'function') {
      setImmediate(() => callback(null, makeFakeClient(), () => {}))
    } else {
      // withTransaction calls pool.connect() as a promise
      return Promise.resolve(makeFakeClient())
    }
  }

  query(text, params) {
    if (!globalThis.__db.queryImpl) throw new Error('globalThis.__db.queryImpl not set')
    return globalThis.__db.queryImpl(text, params)
  }

  async end() {}
}
