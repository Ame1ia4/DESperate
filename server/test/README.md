# Server Security Tests

Uses Node.js built-in test runner (`node:test`) — no extra packages required.

## Run manually

From the **repo root**:

```bash
# All security tests
npm test

# Session management only
npm run test:sessions

# Cryptographic verification only
npm run test:crypto
```

Or directly with node:

```bash
node --test server/test/sessions.test.js
node --test server/test/crypto.test.js
```

## What is tested

### `sessions.test.js`
Session management security properties — no database required.

| Area | What is verified |
|---|---|
| Challenges | 32-byte nonce, single-use, 30s TTL, independent per device |
| Tokens | 64-char hex (256-bit), unique, no PII encoded |
| Single-session | New login on same device invalidates previous token |
| Idle TTL | Session expires after 30 minutes of inactivity |
| Absolute TTL | Session expires after 8 hours regardless of refreshing |
| Deletion | `deleteSession`, `deleteAllSessionsForDevice`, `deleteAllSessionsForUser` all clean up correctly |
| Isolation | Revoking one device does not affect another device or user |

### `crypto.test.js`
`verifyDualSignature` security properties — no database required. Uses real Ed25519 and ML-DSA key generation.

| Area | What is verified |
|---|---|
| Valid signature | Correct dual signature passes |
| Partial attack | Ed25519-only or ML-DSA-only is rejected — both must pass |
| Message tampering | Signature over a different message is rejected |
| Wrong key | Valid signature verified against a different key pair fails |
| Key slot confusion | Swapped or mixed public keys are rejected |
| Malformed inputs | Garbage bytes, empty buffers, truncated keys all return `false` and never throw |
| No short-circuit | Both verifications always run even if the first throws internally |

## CI

Security tests run automatically on every push and pull request to `main` as part of the `Node.js server` job. They are not gated on `HAS_DATABASE` — they always run.

Integration tests (requiring the test database) are a separate step gated on `HAS_DATABASE = true`.
