import { ethers } from 'ethers'
import { query, withTransaction } from '../database/db.js'
import { ABI, CONTRACT_ADDRESS } from './contract.js'

const WORKER_INTERVAL_MS = 20 * 60 * 1000
const BATCH_LIMIT        = 100

// Prevent overlapping runs if a publish takes longer than the interval
let running = false

function buildSigner() {
  const rpcUrl     = process.env.SEPOLIA_RPC_URL
  const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY

  if (!rpcUrl)     throw new Error('SEPOLIA_RPC_URL is not set')
  if (!privateKey) throw new Error('BLOCKCHAIN_PRIVATE_KEY is not set')

  const provider = new ethers.JsonRpcProvider(rpcUrl)
  return new ethers.Wallet(privateKey, provider)
}

export async function publishPendingRoots() {
  const { rows } = await query(
    `SELECT id, merkle_root
     FROM merkle_roots
     WHERE broadcast_to_chain = FALSE
     ORDER BY id ASC
     LIMIT $1`,
    [BATCH_LIMIT]
  )

  if (rows.length === 0) {
    console.log('[blockchain-worker] no pending roots')
    return
  }

  const signer   = buildSigner()
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer)

  // merkle_root is CHAR(66) — trim any trailing whitespace from fixed-length DB column
  const roots = rows.map(r => r.merkle_root.trim())
  const ids   = rows.map(r => r.id)

  const estimated = await contract.storeBatchHashes.estimateGas(roots)
  const tx        = await contract.storeBatchHashes(roots, { gasLimit: estimated * 120n / 100n })
  const receipt   = await tx.wait()

  if (receipt.status !== 1) throw new Error(`tx reverted: ${receipt.hash}`)

  const txHash = receipt.hash

  await withTransaction(async (client) => {
    await client.query(
      `UPDATE merkle_roots
       SET tx_hash = $1, broadcast_to_chain = TRUE
       WHERE id = ANY($2::int[])`,
      [txHash, ids]
    )
  })

  console.log(`[blockchain-worker] published ${rows.length} root(s), tx: ${txHash}`)
}

export function startBlockchainWorker() {
  if (!CONTRACT_ADDRESS || !process.env.BLOCKCHAIN_PRIVATE_KEY) {
    console.warn('[blockchain-worker] BLOCKCHAIN_PRIVATE_KEY or CONTRACT_ADDRESS not set — worker disabled')
    return
  }

  async function run() {
    if (running) {
      console.warn('[blockchain-worker] previous run still in progress, skipping')
      return
    }
    running = true
    try {
      await publishPendingRoots()
    } catch (err) {
      console.error('[blockchain-worker] publish failed')
      if (process.env.NODE_ENV !== 'production') console.error(err)
    } finally {
      running = false
    }
  }

  // Fire immediately on startup, then repeat every 20 minutes
  run()
  setInterval(run, WORKER_INTERVAL_MS)
}
