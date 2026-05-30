import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'

// Set env vars before publisher.js is imported — db-preload.mjs already sets DB_*
process.env.CONTRACT_ADDRESS       ??= '0x' + 'a'.repeat(40)
process.env.BLOCKCHAIN_PRIVATE_KEY ??= '0x' + 'b'.repeat(64)
process.env.SEPOLIA_RPC_URL        ??= 'https://fake-rpc.example.com'

// Mutable so each test can swap behaviour via closure reference
let storeBatchHashesFn
let estimateGasFn

mock.module('ethers', {
  namedExports: {
    ethers: {
      JsonRpcProvider: class {},
      Wallet:          class {},
      Contract: class {
        constructor() {
          this.storeBatchHashes = (roots, opts) => storeBatchHashesFn(roots, opts)
          this.storeBatchHashes.estimateGas = (roots) => estimateGasFn(roots)
        }
      },
    },
  },
})

const { publishPendingRoots, startBlockchainWorker } =
  await import('../../blockchain/publisher.js')

// ── Fixtures ──────────────────────────────────────────────────────────────────

const TX_HASH = '0x' + 'ff'.repeat(32)

// CHAR(66) rows may have trailing padding from PostgreSQL fixed-length columns
function makeRows(n = 1) {
  return Array.from({ length: n }, (_, i) => ({
    id: i + 1,
    merkle_root: '0x' + 'ab'.repeat(32) + ' ',
  }))
}

function okTx(hash = TX_HASH) {
  return { wait: async () => ({ status: 1, hash }) }
}

beforeEach(() => {
  estimateGasFn                      = async () => 1_000_000n
  storeBatchHashesFn                 = async () => okTx()
  globalThis.__db.queryImpl          = async () => ({ rows: makeRows(1) })
  globalThis.__db.clientQueryResults = [{ rows: [] }]
})

// ── publishPendingRoots() ─────────────────────────────────────────────────────

describe('publishPendingRoots()', () => {
  describe('no pending roots', () => {
    it('returns without calling ethers or opening a transaction', async () => {
      globalThis.__db.queryImpl          = async () => ({ rows: [] })
      globalThis.__db.clientQueryResults = [] // throws if transaction runs
      storeBatchHashesFn = () => { throw new Error('must not call storeBatchHashes') }
      await assert.doesNotReject(() => publishPendingRoots())
    })
  })

  describe('SELECT query shape', () => {
    it('filters by broadcast_to_chain = FALSE', async () => {
      let capturedText
      globalThis.__db.queryImpl = async (text) => { capturedText = text; return { rows: makeRows(1) } }
      await publishPendingRoots()
      assert.match(capturedText, /broadcast_to_chain\s*=\s*FALSE/i)
    })

    it('orders by id ASC (oldest-first)', async () => {
      let capturedText
      globalThis.__db.queryImpl = async (text) => { capturedText = text; return { rows: makeRows(1) } }
      await publishPendingRoots()
      assert.match(capturedText, /ORDER BY id ASC/i)
    })

    it('passes 100 as the LIMIT parameter', async () => {
      let capturedParams
      globalThis.__db.queryImpl = async (_t, params) => { capturedParams = params; return { rows: makeRows(1) } }
      await publishPendingRoots()
      assert.deepStrictEqual(capturedParams, [100])
    })
  })

  describe('storeBatchHashes call', () => {
    it('strips trailing CHAR padding whitespace from merkle_root', async () => {
      globalThis.__db.queryImpl = async () => ({
        rows: [{ id: 1, merkle_root: '0x' + 'ab'.repeat(32) + '  ' }],
      })
      let capturedRoots
      storeBatchHashesFn = async (roots) => { capturedRoots = roots; return okTx() }
      await publishPendingRoots()
      assert.strictEqual(capturedRoots[0], '0x' + 'ab'.repeat(32))
    })

    it('sends all roots from the batch in one call', async () => {
      globalThis.__db.queryImpl          = async () => ({ rows: makeRows(3) })
      globalThis.__db.clientQueryResults = [{ rows: [] }]
      let capturedRoots
      storeBatchHashesFn = async (roots) => { capturedRoots = roots; return okTx() }
      await publishPendingRoots()
      assert.strictEqual(capturedRoots.length, 3)
    })

    it('sets gasLimit to estimated gas + 20% buffer', async () => {
      estimateGasFn = async () => 1_000_000n
      let capturedOpts
      storeBatchHashesFn = async (_roots, opts) => { capturedOpts = opts; return okTx() }
      await publishPendingRoots()
      assert.strictEqual(capturedOpts.gasLimit, 1_200_000n)
    })
  })

  describe('DB update after successful tx', () => {
    it('marks the correct row ids as broadcast', async () => {
      globalThis.__db.queryImpl = async () => ({ rows: makeRows(2) })
      let capturedIds
      globalThis.__db.clientQueryResults = [{
        rows: [],
        onCall(_text, params) { capturedIds = params[1] },
      }]
      await publishPendingRoots()
      assert.deepStrictEqual(capturedIds, [1, 2])
    })

    it('stores the transaction hash from the receipt', async () => {
      const hash = '0x' + 'ee'.repeat(32)
      storeBatchHashesFn = async () => okTx(hash)
      let capturedHash
      globalThis.__db.clientQueryResults = [{
        rows: [],
        onCall(_text, params) { capturedHash = params[0] },
      }]
      await publishPendingRoots()
      assert.strictEqual(capturedHash, hash)
    })
  })

  describe('error handling', () => {
    it('throws when receipt.status is 0 (tx reverted on-chain)', async () => {
      storeBatchHashesFn = async () => ({ wait: async () => ({ status: 0, hash: TX_HASH }) })
      await assert.rejects(() => publishPendingRoots(), /reverted/)
    })

    it('throws when storeBatchHashes rejects (e.g. insufficient funds)', async () => {
      storeBatchHashesFn = async () => { throw new Error('insufficient funds') }
      await assert.rejects(() => publishPendingRoots())
    })

    it('throws when the DB SELECT fails', async () => {
      globalThis.__db.queryImpl = async () => { throw new Error('connection timeout') }
      await assert.rejects(() => publishPendingRoots())
    })

    it('throws when the DB update transaction fails', async () => {
      globalThis.__db.clientQueryResults = [{ throwError: new Error('disk full') }]
      await assert.rejects(() => publishPendingRoots())
    })

    it('propagates DB update failure so roots remain pending for the next run', async () => {
      globalThis.__db.clientQueryResults = [{ throwError: new Error('unique violation') }]
      const err = await publishPendingRoots().then(() => null, e => e)
      assert.ok(err instanceof Error)
    })
  })
})

// ── startBlockchainWorker() ───────────────────────────────────────────────────

describe('startBlockchainWorker()', () => {
  it('does not throw when both env vars are set', () => {
    assert.doesNotThrow(() => startBlockchainWorker())
  })

  it('returns without starting when BLOCKCHAIN_PRIVATE_KEY is absent', () => {
    // CONTRACT_ADDRESS is captured at import time from contract.js, so we test
    // the runtime BLOCKCHAIN_PRIVATE_KEY branch of the guard
    const saved = process.env.BLOCKCHAIN_PRIVATE_KEY
    delete process.env.BLOCKCHAIN_PRIVATE_KEY
    assert.doesNotThrow(() => startBlockchainWorker())
    process.env.BLOCKCHAIN_PRIVATE_KEY = saved
  })
})
