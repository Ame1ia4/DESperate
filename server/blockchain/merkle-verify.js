import { ethers } from 'ethers';
import { ABI, CONTRACT_ADDRESS } from './contract.js';
import { queryFilterChunked } from './merkle-core.js';

const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);

const DEPLOY_BLOCK = process.env.CONTRACT_DEPLOY_BLOCK
  ? parseInt(process.env.CONTRACT_DEPLOY_BLOCK, 10)
  : 0;

export async function verifyRoot(merkleRoot) {
  if (!CONTRACT_ADDRESS) throw new Error('CONTRACT_ADDRESS not configured');
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);
  const norm = '0x' + merkleRoot.replace(/^0x/i, '').toLowerCase().padStart(64, '0');

  const latest = await provider.getBlockNumber();
  const logs = await queryFilterChunked(
    contract,
    contract.filters.HashStored(norm),
    DEPLOY_BLOCK,
    latest,
  );

  if (logs.length === 0) return { found: false };

  const log = logs[0];
  const block = await log.getBlock();

  return {
    found:     true,
    txid:      log.transactionHash,
    block:     Number(block.number),
    timestamp: new Date(Number(block.timestamp) * 1000).toISOString(),
  };
}
