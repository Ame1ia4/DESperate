import { ethers } from 'ethers';

const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);

const ABI = ['event HashStored(bytes32 indexed merkleRoot, uint256 timestamp)'];

function getContract() {
  const address = process.env.CONTRACT_ADDRESS;
  if (!address) throw new Error('CONTRACT_ADDRESS not configured');
  return new ethers.Contract(address, ABI, provider);
}

export async function verifyRoot(merkleRoot) {
  const norm = '0x' + merkleRoot.replace(/^0x/i, '').toLowerCase().padStart(64, '0');
  const contract = getContract();

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
