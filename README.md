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
