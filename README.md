# DESperate — Secure Messaging Application
An E2E messagin platform

## Setup

After cloning the repo, run:

```bash
npm run safe-install
```

This installs dependencies safely (no install scripts) and sets up git hooks automatically.

---

## Git Hooks

Hooks live in `.githooks/` and are set up automatically by `safe-install`.

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
DATABASE_URL=postgresql://user:password@localhost:5432/epic
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
.githooks/          git hooks (pre-commit, pre-push, commit-msg)
.github/workflows/  CI pipeline
server/             Node.js backend
cpp_client/         C++ client component
qt_client/          Qt/QML desktop client
blockchain/         Solidity smart contracts
```


--- 

## Cryptography Microservice

### Install
in the crytography folder first run :

python -m venv venv

to create the virtual enviroment

then:
if on mac/linux: 
source venv/bin/activate        
if on windows :
venv\Scripts\activate           

then: 
pip install -r requirements.txt