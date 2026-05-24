# DESperate Cryptography Layer — Design Rationale

## Two Encryption Layers

The AEAD module exposes two separate encryption surfaces with different nonce strategies, because the two use cases have fundamentally different key reuse properties:

**Message encryption (`encrypt` / `decrypt`)** — each message gets a fresh single-use key from the Double Ratchet symmetric ratchet. Because the key is never reused, the nonce can be derived deterministically from the key itself via HKDF. Nonce uniqueness is guaranteed structurally: reusing a (key, nonce) pair would require reusing the message key, which the ratchet prevents.

**Header encryption (`encrypt_header` / `decrypt_header`)** — the same header key is reused across every message in a DH ratchet epoch. Because the key is not single-use, nonce uniqueness cannot be inherited from key uniqueness. A stateful monotonic counter (HeaderCounter) is required instead.

---

## Message Nonce Derivation

The nonce is derived from `(message_key, message_index)` via HKDF rather than being supplied by the caller or drawn from a counter. This:

- **Eliminates an unsafe API surface** — callers cannot accidentally supply a reused nonce.
- **Provides cross-chain domain separation** — different ratchet steps produce different message keys, so identical message indices across chains still yield different nonces.
- **Provides within-chain uniqueness** — different indices produce different HKDF outputs under the same key.

The nonce is derived from `message_key` directly (not a chain index) so domain separation is inherited from the key schedule rather than requiring an additional parameter.

---

## MLS Reuse Guard Omission

MLS §9.3 describes a nonce reuse guard to protect against crash-recovery nonce reuse. We omit it because ratchet state is persisted atomically *before* any message key is returned to the caller. Crash recovery cannot re-derive a previously used key — atomic persistence provides the same guarantee directly. This matches Signal's own implementation.

The wire format is therefore 28 bytes of overhead (`nonce(12) || tag(16)`) rather than 32 bytes.

---

## Constant-Time Nonce Verification

In `decrypt()`, the wire nonce is verified against the expected (re-derived) nonce using `hmac.compare_digest` rather than `==` or a hand-rolled loop. `hmac.compare_digest` is guaranteed constant-time by the CPython implementation and is the stdlib-recommended tool for timing-safe comparison. A nonce mismatch is treated identically to an AEAD tag failure to avoid leaking which check failed.

`hmac.compare_digest` is a stdlib function with its own test suite — it is not separately unit-tested here. Its use in `decrypt()` is covered implicitly by `TestTamperDetection`.

---

## Atomic Persistence

`HeaderCounter` must persist the counter to disk before returning a nonce. A crash between "encrypt with counter N" and "persist counter N" would cause counter N to be reused on recovery — a `(key, nonce)` collision within the session.

Atomicity is achieved via **write-to-temp-then-rename**:

1. Write to a sibling `.tmp` file in the same directory (same filesystem, so the rename is atomic).
2. `fsync` the file descriptor — flushes data from OS buffers to storage.
3. `os.replace()` — atomic rename at the kernel level; readers see either the old file or the new one, never a partial write.
4. `fsync` the directory (POSIX only) — without this, a power loss after the rename but before the directory entry is journaled could cause the new file to disappear on recovery, leaving the stale counter. Windows NTFS makes renames durable without a directory fsync, so this step is skipped on Windows.

The temp file is written to the same directory as the target to ensure both are on the same filesystem — cross-filesystem renames are not atomic.

---

## Crash Recovery Model

If the counter is persisted (step 3 above) but the process crashes before the encrypted message is sent, the counter value is **skipped** (lost) rather than **reused** (unsafe). Losing a nonce value is the safe failure mode.

If `_persist` raises (disk full, permission error, etc.), the in-memory counter is **not** incremented. The caller receives an `OSError` and must not attempt to encrypt — it can retry.

---

## MAX_HEADER_MESSAGES

`MAX_HEADER_MESSAGES = 2**32 - 1` is **not** a nonce space limit. The nonce encodes a full `uint64` (8 bytes), giving `2^64` unique values per header key epoch. The cap is a conservative **key rotation bound**: it forces a DH ratchet step (and therefore a new header key) long before the nonce space is approached. In practice the ratchet rotates the header key far sooner on any reply; this cap exists purely as a safety backstop for pathological one-way message flows.

---

## Counter File Format

The counter file is stored as JSON (`{"session_id": "...", "counter": <int>}`) rather than a compact binary format. JSON is human-readable, making the counter state inspectable during debugging and easier to reason about.

---

## Associated Data Design

Associated data fields must be **length-prefixed** to prevent concatenation ambiguity. Without length prefixes, `b"alice" + b"bob"` and `b"aliceb" + b"ob"` produce identical byte strings, meaning a server could replay an `alice→bob` message as `aliceb→ob`. Length-prefixed fields are unambiguous and bind the direction of the conversation into the authentication tag.

---

## Cross-Session Nonce Uniqueness

Two sessions starting at counter zero will produce identical nonce bytes on their first call. This is **not** nonce reuse because each session has a different header key: `encrypt(key_A, nonce) ≠ encrypt(key_B, nonce)`. Cross-session nonce uniqueness is provided by the header key, not the counter. The counter only guarantees uniqueness *within* a session.

---

## Test Design Notes

**`TestMaxSkip`** — `MAX_SKIP` enforcement lives in the ratchet layer, not in `aead.py` itself. The tests document the contract and confirm the constant is accessible for that check; they do not test enforcement directly.

**`TestDeriveNonce.test_different_key_gives_different_nonce`** — asserts that two different message keys (from different ratchet steps) produce different nonces at the same `message_index`. This is the key property that makes domain separation work: it comes from the key, not a chain index counter.

**`TestEncryptDecryptRoundtrip.test_encryption_is_deterministic`** — encryption is fully deterministic (same inputs → same wire bytes every time) because the reuse guard was removed. This is safe because keys are single-use; the ratchet prevents reuse.

**`TestCrossSessionUniqueness.test_two_sessions_at_counter_zero_have_different_nonces_via_keys`** — deliberately asserts `nonce_a == nonce_b` (the nonce bytes are identical across sessions). This is intentional: the test documents that cross-session safety comes from the differing header keys, not from the counter producing different bytes.

---

## References
1. RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
2. Signal Double Ratchet spec:    https://signal.org/docs/specifications/doubleratchet/
3. MLS protocol draft-17 §9.3:   https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17
4. Signal Double Ratchet spec §4.1 — header encryption nonce: https://signal.org/docs/specifications/doubleratchet/#header-encryption
5. MLS draft-ietf-mls-protocol-17 §9.3 — stateful nonce requirement: https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17