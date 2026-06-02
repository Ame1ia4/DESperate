import { ethers } from 'ethers'
import { query, withTransaction } from './db.js'
import { ABI, CONTRACT_ADDRESS } from './contract.js'
import { buildPendingRoots } from './build-worker.js'
import { loadMerkleConfig } from './config.js'
import { queryFilterChunked } from './merkle-core.js'
import { MERKLE_ADVISORY_LOCK_KEY } from '../constants/blockchain.js'

const DEPLOY_BLOCK = process.env.CONTRACT_DEPLOY_BLOCK
  ? parseInt(process.env.CONTRACT_DEPLOY_BLOCK, 10)
  : 0

let running = false

function buildSigner() {
  const rpcUrl     = process.env.SEPOLIA_RPC_URL
  const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY

  if (!rpcUrl)     throw new Error('SEPOLIA_RPC_URL is not set')
  if (!privateKey) throw new Error('BLOCKCHAIN_PRIVATE_KEY is not set')

  const provider = new ethers.JsonRpcProvider(rpcUrl)
  return new ethers.Wallet(privateKey, provider)
}

// ── Reconciliation ──────────────────────────────────────────────────────────
// Called once on worker start.  Fixes any roots left in state='broadcasting'
// from a previous crash.

async function reconcile(provider) {
  console.info('[publisher] reconcile: starting crash-recovery check')

  // Case A: broadcasting + tx_hash IS NULL — crashed before tx submission
  const { rows: nullTxRoots } = await query(
    `SELECT id, merkle_root
     FROM merkle_roots
     WHERE state = 'broadcasting' AND tx_hash IS NULL`
  )

  if (nullTxRoots.length > 0) {
    console.info(`[publisher] reconcile: ${nullTxRoots.length} root(s) stuck broadcasting with no tx hash — querying chain`)
  }

  for (const row of nullTxRoots) {
    const root = row.merkle_root.trim()
    console.info(`[publisher] reconcile: checking chain for root id=${row.id} ${root.slice(0, 10)}…`)
    try {
      const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider)
      const latest   = await provider.getBlockNumber()
      const logs     = await queryFilterChunked(contract, contract.filters.HashStored(root), DEPLOY_BLOCK, latest)
      if (logs.length > 0) {
        const log    = logs[0]
        const block  = await log.getBlock()
        await withTransaction(async (client) => {
          await client.query(
            `UPDATE merkle_roots
             SET state = 'confirmed', tx_hash = $1, block_timestamp = $2,
                 log_index = $3, confirmed_at = now()
             WHERE id = $4`,
            [log.transactionHash, Number(block.timestamp), log.index, row.id]
          )
          await client.query(
            `UPDATE merkle_leaves SET state = 'confirmed'
             WHERE merkle_root_id = $1`,
            [row.id]
          )
        })
        console.info(`[publisher] reconcile: confirmed root id=${row.id} via HashStored event in tx ${log.transactionHash}`)
      } else {
        await query(`UPDATE merkle_roots SET state = 'built' WHERE id = $1`, [row.id])
        console.info(`[publisher] reconcile: no on-chain event for root id=${row.id} — returned to built`)
      }
    } catch (err) {
      console.error(`[publisher] reconcile: error checking root id=${row.id} ${root.slice(0, 10)}…`, err)
    }
  }

  // Case B: broadcasting + tx_hash IS NOT NULL — tx was submitted, check receipt
  const { rows: pendingTxRoots } = await query(
    `SELECT id, merkle_root, tx_hash
     FROM merkle_roots
     WHERE state = 'broadcasting' AND tx_hash IS NOT NULL`
  )

  if (pendingTxRoots.length > 0) {
    console.info(`[publisher] reconcile: ${pendingTxRoots.length} root(s) with pending tx — checking receipts`)
  }

  for (const row of pendingTxRoots) {
    const txHash = row.tx_hash.trim()
    console.info(`[publisher] reconcile: fetching receipt for tx ${txHash} (root id=${row.id})`)
    try {
      const receipt = await provider.getTransactionReceipt(txHash)

      if (receipt && receipt.status === 1) {
        console.info(`[publisher] reconcile: tx ${txHash} confirmed on-chain (block ${receipt.blockNumber})`)
        await confirmRootsFromReceipt(receipt, [row.id], row.merkle_root.trim())
        console.info(`[publisher] reconcile: root id=${row.id} marked confirmed`)
      } else if (receipt && receipt.status !== 1) {
        console.error(`[publisher] reconcile: tx ${txHash} reverted on-chain — returning root id=${row.id} to built`)
        await query(`UPDATE merkle_roots SET state = 'built' WHERE id = $1`, [row.id])
      } else {
        console.warn(`[publisher] reconcile: tx ${txHash} not found (dropped?) — returning root id=${row.id} to built`)
        await query(`UPDATE merkle_roots SET state = 'built' WHERE id = $1`, [row.id])
      }
    } catch (err) {
      console.error(`[publisher] reconcile: error fetching receipt for tx ${txHash} (root id=${row.id})`, err)
    }
  }

  console.info('[publisher] reconcile: done')
}

// ── Broadcast helpers ────────────────────────────────────────────────────────

async function confirmRootsFromReceipt(receipt, rootIds, /* optional single root for reconcile */ _singleRoot) {
  // Parse HashStored events from the receipt; match each root id to its log.
  const iface = new ethers.Interface(ABI)

  const eventsByRoot = {}
  for (const log of receipt.logs) {
    try {
      const parsed = iface.parseLog(log)
      if (parsed && parsed.name === 'HashStored') {
        const rootHex = parsed.args.merkleRoot.toLowerCase()
        eventsByRoot[rootHex] = { timestamp: Number(parsed.args.timestamp), logIndex: log.index }
      }
    } catch (_) { /* not a HashStored log */ }
  }

  // Load the root values for all ids in this group
  const { rows } = await query(
    `SELECT id, merkle_root FROM merkle_roots WHERE id = ANY($1::int[])`,
    [rootIds]
  )

  await withTransaction(async (client) => {
    for (const row of rows) {
      const rootHex = row.merkle_root.trim().toLowerCase()
      const ev      = eventsByRoot[rootHex]
      if (!ev) {
        console.warn(`[publisher] HashStored event not found for root ${rootHex} in tx ${receipt.hash}`)
        continue
      }

      await client.query(
        `UPDATE merkle_roots
         SET state = 'confirmed', block_timestamp = $1, log_index = $2, confirmed_at = now()
         WHERE id = $3`,
        [ev.timestamp, ev.logIndex, row.id]
      )
      await client.query(
        `UPDATE merkle_leaves SET state = 'confirmed'
         WHERE merkle_root_id = $1`,
        [row.id]
      )
    }
  })
}

// ── Broadcast phase ──────────────────────────────────────────────────────────

async function broadcastBuiltRoots(cfg) {
  const {
    merkle_broadcast_interval_ms:  broadcastIntervalMs,
    merkle_broadcast_min_roots:    minRoots,
    merkle_max_roots_per_tx:       maxRootsPerTx,
    merkle_max_broadcast_attempts: maxAttempts,
  } = cfg

  const { rows: summary } = await query(
    `SELECT COUNT(*)::int AS cnt, MIN(created_at) AS oldest
     FROM merkle_roots
     WHERE state = 'built'`
  )

  const { cnt, oldest } = summary[0]
  console.info(`[publisher] tick: ${cnt} built root(s) awaiting broadcast`)
  if (cnt === 0) return

  const ageMs           = oldest ? Date.now() - new Date(oldest).getTime() : 0
  const shouldBroadcast = cnt >= minRoots || ageMs >= broadcastIntervalMs
  console.info(`[publisher] broadcast trigger: minBatch=${cnt >= minRoots} (${cnt}/${minRoots}), timedOut=${ageMs >= broadcastIntervalMs} (age=${Math.round(ageMs / 1000)}s / ${broadcastIntervalMs / 1000}s)`)
  if (!shouldBroadcast) {
    console.info('[publisher] no broadcast trigger met — waiting')
    return
  }

  // (a) Mark the group as broadcasting BEFORE submitting to the network.
  //     If we crash between here and the tx submission, reconcile() handles it.
  const { rows: builtRoots } = await withTransaction(async (client) => {
    const { rows } = await client.query(
      `SELECT id, merkle_root, attempts
       FROM merkle_roots
       WHERE state = 'built'
       ORDER BY created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [maxRootsPerTx]
    )

    if (rows.length === 0) return { rows: [] }

    const ids = rows.map(r => r.id)
    await client.query(
      `UPDATE merkle_roots
       SET state = 'broadcasting', broadcast_at = now(), attempts = attempts + 1
       WHERE id = ANY($1::int[])`,
      [ids]
    )

    return { rows }
  })

  if (builtRoots.length === 0) return

  const ids   = builtRoots.map(r => r.id)
  const roots = builtRoots.map(r => r.merkle_root.trim())

  console.info(`[publisher] dispatching ${roots.length} root(s): ${roots.map(r => r.slice(0, 10) + '…').join(', ')}`)

  try {
    const signer   = buildSigner()
    const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer)

    const estimated = await contract.storeBatchHashes.estimateGas(roots)
    const tx        = await contract.storeBatchHashes(roots, { gasLimit: estimated * 120n / 100n })

    // (b) Persist tx_hash immediately — BEFORE awaiting confirmation.
    await query(
      `UPDATE merkle_roots SET tx_hash = $1 WHERE id = ANY($2::int[])`,
      [tx.hash, ids]
    )
    console.info(`[publisher] tx submitted: ${tx.hash} (${roots.length} roots)`)

    // (c) Wait for confirmation; decode per-root block_timestamp + log_index.
    const receipt = await tx.wait()
    if (receipt.status !== 1) throw new Error(`tx reverted: ${receipt.hash}`)

    await confirmRootsFromReceipt(receipt, ids)
    console.info(`[publisher] confirmed: ${tx.hash}`)

  } catch (err) {
    console.error('[publisher] broadcast error:', err?.message ?? err)

    // Retry or fail each root individually based on attempts
    for (const row of builtRoots) {
      if (row.attempts + 1 >= maxAttempts) {
        await query(
          `UPDATE merkle_roots SET state = 'failed' WHERE id = $1`,
          [row.id]
        )
        console.error(`[publisher] root id=${row.id} permanently failed after ${maxAttempts} attempts`)
      } else {
        await query(
          `UPDATE merkle_roots SET state = 'built' WHERE id = $1`,
          [row.id]
        )
      }
    }
  }
}

// ── Combined worker ──────────────────────────────────────────────────────────

export function startBlockchainWorker() {
  if (!CONTRACT_ADDRESS || !process.env.BLOCKCHAIN_PRIVATE_KEY) {
    console.warn('[blockchain-worker] BLOCKCHAIN_PRIVATE_KEY or CONTRACT_ADDRESS not set — worker disabled')
    return
  }

  let cfg = null

  async function run() {
    if (running) {
      console.warn('[blockchain-worker] previous run still in progress, skipping')
      return
    }
    running = true
    console.info('[blockchain-worker] tick starting')

    try {
      // Acquire advisory lock so concurrent workers never double-anchor
      await query(`SELECT pg_advisory_lock($1)`, [MERKLE_ADVISORY_LOCK_KEY])

      await buildPendingRoots(cfg)
      await broadcastBuiltRoots(cfg)

    } catch (err) {
      console.error('[blockchain-worker] tick error:', err?.message ?? err)
      if (process.env.NODE_ENV !== 'production') console.error(err)
    } finally {
      try {
        await query(`SELECT pg_advisory_unlock($1)`, [MERKLE_ADVISORY_LOCK_KEY])
      } catch (_) { /* ignore unlock errors */ }
      running = false
    }
  }

  async function start() {
    cfg = await loadMerkleConfig()

    // Reconcile any in-flight roots from a previous crash
    const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL)
    await reconcile(provider).catch(err =>
      console.error('[blockchain-worker] reconcile error:', err?.message ?? err)
    )

    // Fire immediately, then repeat at the worker tick cadence
    run()
    setInterval(run, cfg.merkle_worker_tick_ms)
  }

  start().catch(err => console.error('[blockchain-worker] start error:', err))
}

// Export for tests
export { buildPendingRoots, broadcastBuiltRoots, reconcile }
