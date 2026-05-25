# MessageIntegrity — Developer Notes

---

## Contract — `MessageIntegrity`

### Purpose

The blockchain's role in this system is tamper-evident storage. Once a Merkle
root is recorded on-chain it cannot be altered or deleted by any party —
including the server. This is enforced by the Ethereum network, not by any
single party.

Client authenticity is guaranteed at the messaging layer by ML-DSA
(post-quantum) signatures verified off-chain by recipients. The blockchain
layer and the messaging layer are independent — each handles the security
property it is best suited for.

### Verification model

We hash the ciphertext of a message and store that client-side. After X
messages have been hashed, build those hashes into a Merkle root — only the
root is sent to the server. Client-side, we still have the message hashes, and
those hashes will point to the computed Merkle root.

For the verification page, the client just needs to input the Merkle root and
that root will be verified on the blockchain.

We can further verify (extra feature, not core) that a specific message exists
by inputting a message or ciphertext hash and confirming that hash exists in
the verified Merkle root — therefore it is stored on the blockchain.

### Threat model

A fully compromised server controls the wallet that pays gas and could submit
fraudulent roots. These are unverifiable orphans — no client Merkle tree will
ever produce a root matching them, so no verify-page check will ever surface
them. The integrity guarantee — "a root, once recorded, cannot be changed" —
is fully preserved even against a compromised server.

A compromised server also knows the wallet private key and could exhaust the
Sepolia ETH balance by spamming transactions, denying future legitimate
submissions until the wallet is refunded. This is a known limitation.

### Immutability

This contract is intentionally non-upgradeable:

- `owner` is `immutable` — baked into bytecode at deployment, irrevocable
  without redeployment.
- No `selfdestruct`, no proxy pattern, no admin functions.
- Stored timestamps and existence flags are never modified after writing.

### Reentrancy

Structurally immune — no ETH is held or transferred, no external calls are
made, and no `payable`, `receive`, or `fallback` functions exist. CEI order is
maintained throughout both write functions. A `ReentrancyGuard` would add gas
cost for zero benefit and is deliberately omitted.

---

## State variables

### `timestamps` — `mapping(bytes32 => uint256) private`

Private — callers must use `getTimestamp`, which returns the `found` flag
alongside the timestamp. Exposing this mapping as public would allow callers
to read a zero timestamp for an unstored root with no indication it was never
recorded.

### `rootExists` — `mapping(bytes32 => bool) private`

Used as the duplicate guard and the "not found" sentinel. Kept separate from
`timestamps` rather than checking `timestamps[root] == 0` because timestamp
zero is theoretically valid on some EVM-compatible chains. The explicit boolean
makes intent unambiguous and the contract portable.

### `_count` — `uint256 private`

Incremented inside both `storeHash` and `storeBatchHashes`. Exposed via
`recordCount()`. Cheaper to maintain a counter than an array purely for its
`.length` property.

---

## Custom errors

### `ZeroRoot(uint256 index)`

For single submissions the index is always 0. For batch submissions the index
identifies exactly which position in the array was zero, so the server can
remove it and retry without guessing.

### `DuplicateRoot(uint256 index, bytes32 merkleRoot)`

Carries both the array index and the root value so the server can
unambiguously identify the duplicate. For single submissions the index is
always 0. Reverts the entire transaction — no partial writes occur.

---

## Events

### `HashStored(bytes32 indexed merkleRoot, uint256 timestamp)`

The server stores the Ethereum transaction hash returned after each submission
and maps it to the corresponding messages in its database. The verify page uses
that transaction hash to retrieve this event from the receipt, confirming which
root was recorded and when. `merkleRoot` is indexed to allow efficient log
filtering by root value without reading contract state.

---

## Constructor

### `constructor(address _owner)`

`owner` is written as `immutable` — its value is inlined into bytecode at
deployment and cannot be changed by any subsequent call. No ETH is accepted at
construction or at any later point; the absence of `payable`, `receive`, and
`fallback` means accidental ETH sends are rejected by the EVM.

---

## Write functions

### `storeHash(bytes32 merkleRoot)`

Use `storeBatchHashes` when submitting multiple roots — it pays the 21,000 gas
base transaction cost once rather than once per root. `storeHash` is provided
for single submissions and testing.

The owner check runs first (fail fast on auth before touching storage). Input
guards follow. State writes are last with event emission at the end — CEI order
throughout, no external calls.

### `storeBatchHashes(bytes32[] calldata merkleRoots)`

Pays the 21,000 gas base transaction cost once regardless of batch size. Each
root is independently queryable via `getTimestamp` after the call. All roots in
the batch share the same `block.timestamp` — they land in the same block.

The owner check runs before the loop (fail fast on auth, and avoids redundant
checks on every iteration). The empty-batch and size-cap guards follow.
Per-root guards run inside the loop.

Batch size is capped at `MAX_BATCH_SIZE` roots. Without a cap, a sufficiently
large array could hit the Ethereum block gas limit, producing an opaque
out-of-gas revert rather than a clean error. The cap gives the server a clear
signal to split oversized batches before submitting.

If any root is invalid the entire transaction reverts — no partial writes
occur. The custom error identifies exactly which index failed and why, so the
server can remove that entry and resubmit without guessing.

---

## Read functions

### `getTimestamp(bytes32 merkleRoot)`

Primary entry point for the verify page. The client recomputes the Merkle root
locally — `keccak256(message)` produces the leaf, the locally stored proof
path (sibling hashes) is walked to recompute the root — and passes it here. No
server involvement is required for verification.

Callers **must** check `found` before trusting `timestamp`. If `found` is
false, `timestamp` is zero and has no meaning.

### `recordCount()`

Backed by the `_count` counter rather than an array length. Useful for
confirming submissions were relayed and for off-chain tooling monitoring
contract activity.
