# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DESperate is a secure end-to-end encrypted messaging platform (student course project). It is a monorepo with a planned multi-component architecture:

- `server/` — Node.js backend (currently the only enabled component)
  - `server/database/` — PostgreSQL schema (`schema.sql`)
- `client/` — Client-side components; the server must never access or depend on anything here
  - `client/cryptography/` — Python E2EE cryptography microservice (AEAD, double ratchet, post-quantum)
- `cpp_client/` — C++ desktop client
- `qt_client/` — Qt/QML desktop client
- `blockchain/` — Solidity smart contracts (Ethereum, Hardhat)

Most sub-projects are scaffolded but not yet implemented. CI feature flags gate each component.

## CI Feature Flags

Sub-projects are enabled in `.github/workflows/ci.yml` via GitHub Actions variables:

| Variable | Default | Enable when |
|---|---|---|
| `HAS_SERVER` | `true` | Already enabled |
| `HAS_DATABASE` | `false` | DB schema is ready for CI |
| `HAS_CPP` | `false` | C++ client is buildable |
| `HAS_QT` | `false` | Qt client is buildable |
| `HAS_BLOCKCHAIN` | `false` | Contracts compile and test |

To enable a component, set the variable to `true` in GitHub Actions → Settings → Variables.

## Build & Package Management

- Node.js version: 20
- Setup hooks: `npm run setup` (run once after clone)
- **Never run `npm install` directly** — the pre-commit hook enforces that `package-lock.json` is updated whenever `package.json` changes. Use `npm ci` for clean installs.
- `.npmrc` enforces: `save-exact=true`, `ignore-scripts=true`, `audit-level=high`, `allow-git=none`, `min-release-age=5`

## Security Requirements

This is an E2EE system — security correctness is critical.

- **No secrets in code**: CI scans for `private_key=`, `password=`, `secret=`, `api_key=` patterns with 8+ char values. Pre-commit hook also blocks `.env` files and PEM private keys.
- **Keccak256 only**: Merkle tree hashing on the server side MUST use keccak256 (not SHA-256) to match on-chain Solidity verification.
- **No hardcoded IVs**: C++ code is scanned for `iv = {` patterns.
- **Argon2id**: Password hashing uses Argon2id — do not substitute other hash functions.
- **No plaintext or private keys ever stored in the database**.
- CI runs `npm audit --audit-level=high` for the server; fix or justify any high/critical findings before merging.

## Database Architecture (PostgreSQL 16)

The server stores encrypted ciphertext it cannot decrypt (Signal/WhatsApp-style design).

Key design decisions:
- **Messages table** (`messages`): Immutable permanent record of ciphertext + nonce + authenticated metadata.
- **Message queue** (`message_queue`): Transient per-device delivery state — purged after ACK or expiry. Do not conflate with `messages`.
- **Soft delete**: Messages are never hard-deleted immediately; a 24-hour grace period applies before cleanup of soft-deleted rows.
- **Prekey architecture**: Identity key, signed prekey, one-time prekeys (OPK), last-resort OPK per device.
- **Post-quantum crypto**: `idk_pq_pub` columns are nullable — post-quantum support (ML-KEM/Kyber, ML-DSA) is optional/future.
- **Merkle roots** (`merkle_roots`): Anchors Ethereum tx hashes using keccak256. The `tx_hash` column stores the on-chain transaction reference.

Schema lives at `server/database/schema.sql`. Test DB credentials (CI only): user `epic`, password `epic_test`, database `epic_test`.

## Deployment

- SSH auto-deploy to server on push to `main` (requires GitHub Secrets: `SERVER_HOST`, `SERVER_USER`, `SERVER_SSH_KEY`).
- Process manager: pm2.

## Environment Variables

See `.env.example` for required variables. Key ones:
- `DATABASE_URL` — PostgreSQL connection string
- `BLOCKCHAIN_PRIVATE_KEY` — Ethereum signing key (never commit)
- `PORT`, `NODE_ENV`, `AUTH_SECRET`
- `SSL_CERT_PATH`, `SSL_KEY_PATH`
