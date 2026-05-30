"""
main.py — TCP RPC server for E2EE cryptography operations.

Listens on 127.0.0.1:54231. Protocol: newline-delimited JSON.
  Request:  {"id": "<uuid>", "method": "<name>", "params": {...}}\n
  Response: {...}\n
"""
import asyncio
import json
import logging
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.keys import generate_identity_bundle as _gen_bundle
from core.state_store import StateStore
from cryptography.exceptions import InvalidTag

HOST = "127.0.0.1"
PORT = 54231
KEYSTORE_DIR = Path.home() / ".desperate" / "keystore"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Handlers ──────────────────────────────────────────────────────────────────


async def handle_unlock_keystore(params: dict) -> dict:
    password = params.get("password", "")
    if not password:
        return {"success": False, "error": "Password required."}
    try:
        store = StateStore.load(KEYSTORE_DIR, password)
        store.load_state("identity")  # raises InvalidTag on wrong password
        return {"success": True}
    except FileNotFoundError:
        return {"success": False, "error": "No keystore found. Register first."}
    except InvalidTag:
        return {"success": False, "error": "Invalid password."}
    except Exception as exc:
        log.exception("unlock_keystore failed")
        return {"success": False, "error": str(exc)}


async def handle_generate_identity_bundle(params: dict) -> dict:
    password = params.get("password", "")
    user_id = params.get("user_id", "local")
    if not password:
        return {"error": "Password required."}
    try:
        # Wipe any existing keystore before creating a fresh identity
        if KEYSTORE_DIR.exists():
            shutil.rmtree(KEYSTORE_DIR)
        bundle = _gen_bundle(user_id)
        store = StateStore.create(KEYSTORE_DIR, password)
        store.save_state("identity", bundle.to_private_bundle())
        return bundle.to_public_bundle()
    except Exception as exc:
        log.exception("generate_identity_bundle failed")
        return {"error": str(exc)}


HANDLERS = {
    "unlock_keystore": handle_unlock_keystore,
    "generate_identity_bundle": handle_generate_identity_bundle,
}

# ── Connection handling ────────────────────────────────────────────────────────


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peer = writer.get_extra_info("peername")
    log.info("connection from %s", peer)
    try:
        async for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                writer.write(
                    json.dumps({"error": "Invalid JSON"}).encode() + b"\n"
                )
                await writer.drain()
                continue

            method = request.get("method", "")
            params = request.get("params", {})

            handler = HANDLERS.get(method)
            if handler is None:
                response = {"error": f"Unknown method: {method!r}"}
            else:
                response = await handler(params)

            writer.write(
                json.dumps(response, separators=(",", ":")).encode() + b"\n"
            )
            await writer.drain()
    except asyncio.IncompleteReadError:
        pass
    except Exception:
        log.exception("error handling client %s", peer)
    finally:
        writer.close()
        await writer.wait_closed()
        log.info("disconnected %s", peer)


# ── Entry point ───────────────────────────────────────────────────────────────


async def serve() -> None:
    server = await asyncio.start_server(handle_client, HOST, PORT)
    log.info("crypto service listening on %s:%d", HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
