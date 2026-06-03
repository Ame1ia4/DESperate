# DESperate — Secure Messaging Application

A secure, end-to-end encrypted messaging platform built for the EPIC project. Provides confidentiality, integrity, and authenticity of communications using modern cryptographic primitives, a blockchain integrity layer, and a hybrid Qt/Python/C++ client stack.

---

## Table of Contents

- [Running Client](#running-client)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Running the Server](#running-the-server)
- [Database Migrations](#database-migrations)
- [Qt Desktop Client](#qt-desktop-client)
- [Cryptography Microservice](#cryptography-microservice)
- [Blockchain / Smart Contracts](#blockchain--smart-contracts)
- [CI/CD](#cicd)
- [Git Hooks](#git-hooks)
- [Environment Variables](#environment-variables)
- [Project Structure](#project-structure)

---

## Running Client
Build Steps 

    Clone and navigate to the client  

    cd client/secure_messenger  

    Configure (OpenSSL path set in CMakeLists.txt; override if needed)  

    cmake -B build -DCMAKE_BUILD_TYPE=Release  

    Build — CMake will auto-rebuild the crypto_service PyInstaller bundle if Python + PyInstaller are found; otherwise start the crypto service manually:  

    # cd client/cryptography && python crypto_service.py  

    cmake --build build --config Release  

    Run  

    ./build/appsecure_messenger # Linux/macOS  

    build\Release\appsecure_messenger.exe # Windows

---

## Architecture Overview

```
Internet ──[TLS 1.2/1.3]──► Gateway ──[HTTP]──► VM (port 80)
                                                      │
                                          ┌───────────┴───────────┐
                                      Node.js Server          PostgreSQL
                                          │
                              ┌───────────┴───────────┐
                          Qt Client              Python Crypto
                          (Windows)               Microservice
                              │
                          C++ Client Component
```

**SSL termination** happens at the gateway — traffic from the internet is fully encrypted (TLS 1.2/1.3), and your VM only needs to serve on port 80. Do not configure SSL on the VM itself.

> ⚠️ If nothing is listening on port 80, visitors will see a `503 Service Unavailable` error.

---

## Prerequisites

| Component | Requirement |
|---|---|
| Node.js server | Node.js 18+, PostgreSQL 16 |
| Qt client | Qt 6.11.1 (MinGW 64-bit kit), OpenSSL dev libraries |
| Crypto service | Python 3.11+, PyInstaller |
| Blockchain | Node.js, Hardhat |

---

## Quick Start

Clone the repo and install dependencies:

```bash
git clone <repo-url>
cd desperate
npm run setup   # configures git hooks
npm install     # installs server dependencies
```

Copy the environment file and fill in your values:

```bash
cp .env.example .env
```

Required variables:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/desperate
BLOCKCHAIN_PRIVATE_KEY=0x...
NODE_ENV=development
```

---

## Running the Server

The server runs via **PM2**, a process manager that keeps Node.js alive across SSH disconnects and VM reboots. Run all commands from the `server/` directory.

### Start

```bash
sudo pm2 start server.js --name des-perate
```

### Stop / Restart

```bash
sudo pm2 stop des-perate
sudo pm2 restart des-perate
```

### Status & Logs

```bash
sudo pm2 status
sudo pm2 logs des-perate
```

### Survive VM Reboots

Run once after the first start:

```bash
sudo pm2 save
sudo pm2 startup
# Copy and run the command that pm2 startup prints
```

### Keep PM2 Updated

> ⚠️ CVE-2025-5891 affected PM2 versions below 6.0.9. Keep it updated:

```bash
sudo npm install -g pm2@latest
sudo pm2 restart des-perate
```

---

## Database Migrations

`schema.sql` is the **baseline** — run it once on a fresh database only. All structural changes after that must go through migrations, never edits to `schema.sql`.

### Apply All Pending Migrations

```bash
npm run migrate
```

### Undo the Last Migration

```bash
npm run migrate:down
```

### Create a New Migration

```bash
npm run migrate:create -- your_description_here
```

This creates a timestamped file in `migrations/`. Edit it:

```js
export const up = (pgm) => {
  pgm.addColumn('devices', {
    push_token: { type: 'varchar(255)', notNull: false }
  })
}

export const down = (pgm) => {
  pgm.dropColumn('devices', 'push_token')
}
```

**Rules:**
- Never edit a migration that has already been run
- If you made a mistake, create a new migration to fix it
- Always commit migration files so the server and all team members stay in sync

---

## Qt Desktop Client

### Prerequisites

- Qt 6.11.1 — install via Qt Maintenance Tool, select the **MinGW 64-bit** kit
- OpenSSL dev libraries (required for the `TLSManager` component)

**Windows (MinGW):** The standard Shining Light OpenSSL installer ships MSVC-only libs. Use MSYS2 instead:

```bash
# 1. Install MSYS2 if not already installed
winget install MSYS2.MSYS2

# 2. Open the MSYS2 MinGW64 terminal and run:
pacman -S mingw-w64-x86_64-openssl
```

Then in Qt Creator: **Projects → Build → CMake → Add**

| Name | Type | Value |
|---|---|---|
| `OPENSSL_ROOT_DIR` | `PATH` | `C:\msys64\mingw64` |

**Linux / macOS:**

```bash
sudo apt install libssl-dev   # Ubuntu/Debian
brew install openssl          # macOS
```

### Build

Open `client/secure_messenger/CMakeLists.txt` in Qt Creator and build normally, or from the terminal:

```bash
cmake -B build -S client/secure_messenger -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

### Run Tests

In Qt Creator: **View → Views → Tests**, then right-click any test to run it.

Or from the terminal:

```bash
ctest --test-dir build --output-on-failure
```

---

## Cryptography Microservice

The crypto service is a Python TCP server (`client/cryptography/main.py`) that handles all E2EE key operations for the Qt client. It must be compiled into a self-contained executable before the Qt app can auto-start it.

### Prerequisites

- Python 3.11+
- CMake and MinGW GCC — both ship with Qt at:
  - `C:\Qt\Tools\CMake_64\bin`
  - `C:\Qt\Tools\mingw1310_64\bin`

### Install Dependencies

```bash
cd client/cryptography
pip install -r requirements.txt
pip install pyinstaller
```

### Build the Executable

**PowerShell:**

```powershell
$env:PATH = "C:\Qt\Tools\CMake_64\bin;C:\Qt\Tools\mingw1310_64\bin;$env:PATH"
$env:CMAKE_GENERATOR = "MinGW Makefiles"
python -m PyInstaller crypto_service.spec
```

**Git Bash / MSYS2:**

```bash
export PATH="/c/Qt/Tools/CMake_64/bin:/c/Qt/Tools/mingw1310_64/bin:$PATH"
export CMAKE_GENERATOR="MinGW Makefiles"
python -m PyInstaller crypto_service.spec
```

This produces `dist/crypto_service/crypto_service.exe` with `liboqs.dll` and all dependencies bundled — no Python required on the end-user machine.

> The first build compiles `liboqs` from source into `C:\Users\<you>\_oqs`. This takes a few minutes but only happens once per machine.

### Wire into Qt Creator

After building, rebuild the Qt project in Qt Creator. The CMake post-build step copies `dist/crypto_service/` next to the Qt binary automatically. The Qt app then auto-starts the service on login/signup.

### Rebuild After Changes

Re-run `python -m PyInstaller crypto_service.spec`, then rebuild in Qt Creator.

### Run Tests

```bash
cd client/cryptography
pytest
```

---

## Blockchain / Smart Contracts

The `blockchain/` folder contains the `MessageIntegrity` Solidity contract deployed to the **Ethereum Sepolia testnet**. Message conversation digest hashes (keccak256) are periodically recorded on-chain for tamper-evident integrity verification.

### Setup

```bash
cd blockchain
npm ci
```

### Compile

```bash
npx hardhat compile
```

### Run Tests

```bash
npx hardhat test
```

The test suite covers all contract functions, error cases, ETH rejection, and the no-partial-write guarantee (25 tests total).

---

## CI/CD

GitHub Actions runs automatically on every push to `main` or `dev`. Jobs are toggled by feature flags at the top of `.github/workflows/ci.yml`:

```yaml
HAS_SERVER:     true
HAS_DATABASE:   false   # flip when postgres is ready
HAS_CPP:        false   # flip when C++ client is ready
HAS_QT:         false   # flip when Qt client is ready
HAS_BLOCKCHAIN: false   # flip when contracts are ready
```

The security scan always runs regardless of flags.

For auto-deploy, add these to **GitHub → Settings → Secrets → Actions**:

| Secret | Value |
|---|---|
| `SERVER_HOST` | Server IP address |
| `SERVER_USER` | SSH username |
| `SERVER_SSH_KEY` | Private SSH key |

---

## Git Hooks

Hooks live in `.githooks/` and are configured via `npm run setup`.

| Hook | Trigger | What it does |
|---|---|---|
| `pre-commit` | Before every commit | Blocks `.env` files and private keys; runs `npm audit` on server changes |

---

## Environment Variables

Never commit `.env` files. Copy the example and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `BLOCKCHAIN_PRIVATE_KEY` | Ethereum wallet private key for contract transactions |
| `NODE_ENV` | `development` or `production` |

---

## Project Structure

```
.githooks/                   Git hooks (pre-commit, pre-push, commit-msg)
.github/workflows/           CI pipeline
server/                      Node.js backend
  server/database/           PostgreSQL schema and migrations
client/                      Client-side components
  client/cryptography/       Python E2EE cryptography microservice
  client/secure_messenger/   Qt/QML desktop client
cpp_client/                  C++ client component
blockchain/                  Solidity smart contracts (Sepolia testnet)
```