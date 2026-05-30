# DESperate — Secure Messaging Application
An E2E messagin platform

## Setup

After cloning the repo, run:

```bash
npm run setup
npm install
```

This ensures everyone is using the same githooks folder rather than the local git/hooks.
npm install installs the required packages obv

---

## Run Server
These commands are if you are in the server/ directory.

### Why PM2
PM2 is a process manager for Node.js. Without it, the server stops the moment you
close your SSH session. PM2 keeps it running in the background, automatically restarts
it if it crashes, and starts it again on VM reboot.

### Starting the server
to start the server, run this in the VM:

```bash
sudo pm2 start server.js --name des-perate
```

### Stopping the server
```bash
sudo pm2 stop des-perate
```

### Restarting the server
```bash
sudo pm2 restart des-perate
```
### Checking status
```bash
sudo pm2 status
```

### Viewing live logs
```bash
sudo pm2 logs des-perate
```

### Survive VM reboots
Run this once after first starting the server:
```bash
sudo pm2 save
sudo pm2 startup
```
Follow the command that `pm2 startup` prints — it will give you a line to copy and run.

### Updating PM2
```bash
sudo npm install -g pm2@latest
sudo pm2 restart des-perate
```
Keep PM2 updated — CVE-2025-5891 affected versions below 6.0.9 so make sure the version isn't below that.

---

## Git Hooks

Hooks live in `.githooks/`.

| Hook | When | What it does |
|---|---|---|
| `pre-commit` | before every commit | blocks `.env` files, private keys, runs npm audit on server changes |

## Environment Variables

Never commit `.env` files. Copy the example and fill in your values:

```bash
cp .env.example .env
```

Required variables:
```
DATABASE_URL=postgresql://user:password@localhost:...
BLOCKCHAIN_PRIVATE_KEY=0x...
NODE_ENV=development
```

---

## Database Migrations

The `schema.sql` file is the baseline — run it once on a fresh database only.
All structural changes after that must be migrations, never edits to `schema.sql`.

### Creating a migration

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

### Running migrations

```bash
npm run migrate        # apply all pending migrations
npm run migrate:down   # undo the last migration
```

Safe to run multiple times — already-applied migrations are skipped automatically.

### Rules

- Never edit a migration that has already been run on the database
- If you made a mistake, create a new migration to fix it
- Always commit migration files to the repo so the server and all team members stay in sync

---

## CI/CD

GitHub Actions runs automatically on every push to `main` or `dev`.

Jobs are toggled by feature flags at the top of `.github/workflows/ci.yml`:

```yaml
HAS_SERVER:     true
HAS_DATABASE:   false   # flip when postgres is ready
HAS_CPP:        false   # flip when C++ client is ready
HAS_QT:         false   # flip when Qt client is ready
HAS_BLOCKCHAIN: false   # flip when contracts are ready
```

The security scan always runs regardless of flags.

For auto-deploy to work, add these to GitHub Secrets (repo → Settings → Secrets → Actions):
- `SERVER_HOST` — server IP address
- `SERVER_USER` — SSH username
- `SERVER_SSH_KEY` — private SSH key

---

## Project Structure

```
.githooks/               git hooks (pre-commit, pre-push, commit-msg)
.github/workflows/       CI pipeline
server/                  Node.js backend
  server/database/       PostgreSQL schema
client/                  Client-side components (no server access to these)
  client/cryptography/   Python E2EE cryptography microservice
cpp_client/              C++ client component
qt_client/               Qt/QML desktop client
blockchain/              Solidity smart contracts
```


---

## Blockchain / Smart Contracts

The `blockchain/` folder contains the `MessageIntegrity` Solidity contract and its Hardhat test suite.

### Setup

```bash
cd blockchain
npm ci
```

### Compile

```bash
npx hardhat compile
```

### Run tests

```bash
npx hardhat test
```

Tests cover all contract functions, error cases, ETH rejection, and the no-partial-write guarantee. 25 tests total.

### CI

Set `HAS_BLOCKCHAIN` to `true` in GitHub → Settings → Actions → Variables to enable the blockchain job in CI.

---

## Qt Client (`client/secure_messenger`)

### Prerequisites

- Qt 6.11.1 (install via Qt Maintenance Tool, select the MinGW 64-bit kit)
- OpenSSL dev libraries — required because `TLSManager` uses raw OpenSSL APIs directly

**Windows (MinGW):** OpenSSL must be installed via MSYS2 — the standard Shining Light installer only ships MSVC libs which MinGW can't link against.

```bash
# 1. Install MSYS2 (skip if already installed)
winget install MSYS2.MSYS2

# 2. Open the MSYS2 MinGW64 terminal (not the plain MSYS2 terminal) and run:
pacman -S mingw-w64-x86_64-openssl
```

Then in Qt Creator: **Projects → Build → CMake → Add**
- Name: `OPENSSL_ROOT_DIR`
- Type: `PATH`
- Value: `C:\msys64\mingw64`

**Linux/macOS:**
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

### Run tests

In Qt Creator: **View → Views → Tests**, then right-click any test to run it.

Or from the terminal:
```bash
ctest --test-dir build --output-on-failure
```

### CI

Set `HAS_QT` to `true` in GitHub → Settings → Actions → Variables to enable the Qt client job in CI.

---

## Cryptography Microservice

### Install
in the `client/cryptography/` folder first run:

python -m venv venv

to create the virtual enviroment

then:
if on mac/linux: 
source venv/bin/activate        
if on windows :
venv\Scripts\activate           

then: 
pip install -r requirements.txt
