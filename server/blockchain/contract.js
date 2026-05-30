export const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;

export const ABI = [
  {
    "anonymous": false,
    "inputs": [
      { "indexed": true,  "internalType": "bytes32", "name": "merkleRoot", "type": "bytes32" },
      { "indexed": false, "internalType": "uint256", "name": "timestamp",  "type": "uint256" }
    ],
    "name": "HashStored",
    "type": "event"
  },
  {
    "inputs": [{ "internalType": "bytes32[]", "name": "merkleRoots", "type": "bytes32[]" }],
    "name": "storeBatchHashes",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
];
