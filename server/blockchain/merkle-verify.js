import { ethers } from 'ethers';
import { ABI, CONTRACT_ADDRESS } from './contract.js';

if (!CONTRACT_ADDRESS) throw new Error('CONTRACT_ADDRESS not configured');

const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

export async function verifyRoot(merkleRoot) {
  const norm = '0x' + merkleRoot.replace(/^0x/i, '').toLowerCase().padStart(64, '0');

  const logs = await contract.queryFilter(contract.filters.HashStored(norm));

  if (logs.length === 0) return { found: false };

  const log = logs[0];
  const block = await log.getBlock();

  return {
    found: true,
    txid: log.transactionHash,
    timestamp: new Date(Number(block.timestamp) * 1000).toISOString(),
  };
}
