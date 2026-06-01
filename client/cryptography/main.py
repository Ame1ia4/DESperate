"""
main.py — TCP RPC server for E2EE cryptography operations.

Listens on 127.0.0.1:54231. Protocol: newline-delimited JSON.
  Request:  {"id": "<uuid>", "method": "<name>", "params": {...}}\n
  Response: {"id": "<uuid>", ...}\n

Session architecture
--------------------
SRP:
  srp_start  → create SrpSession, return A
  srp_challenge → process salt+B, return M1
  srp_verify → verify M2, return session_key (the SRP K hex)

PQXDH + symmetric encryption:
  initiate_session → PQXDH initiation; SK stored in _session_keys[conv_id]
  encrypt_message  → ChaCha20-Poly1305 with SK; first call includes PQXDH bundle
  decrypt_message  → ChaCha20-Poly1305; auto-responds to PQXDH if initiation_bundle present
"""
import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

import srp as _srp_lib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from core.keys import (
    IdentityBundle,
    generate_identity_bundle as _gen_bundle,
)
from core.pqxdh import initiate as pqxdh_initiate, respond as pqxdh_respond
from core.srp_session import SrpSession, _SRP_3072_KWARGS
from core.state_store import StateStore

HOST = "127.0.0.1"
PORT = 54231
KEYSTORE_DIR = Path.home() / ".desperate" / "keystore"
_registration_lock = asyncio.Lock()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Service-lifetime state ────────────────────────────────────────────────────

# Keystore handle, available after unlock_keystore or generate_identity_bundle.
_keystore_store: Optional[StateStore] = None
_keystore_password: Optional[str] = None

# SRP client session — one active session at a time (single-user service).
_srp_session: Optional[SrpSession] = None

# Per-conversation symmetric keys derived via PQXDH.
# {conversation_id: bytes}  — 32-byte ChaCha20 key (= SK from PQXDH)
_session_keys: dict[str, bytes] = {}

# PQXDH initiation bundles to include in the FIRST encrypt_message call
# for each new conversation so the responder can derive the same SK.
# {conversation_id: dict}  — InitiationBundle.to_dict()
_pending_initiation_bundles: dict[str, dict] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_identity() -> Optional[IdentityBundle]:
    """
    Load the identity bundle from the keystore if unlocked.
    Returns None if keystore is not yet unlocked.
    """
    if _keystore_store is None:
        return None
    try:
        private_data = _keystore_store.load_state("identity")
        return IdentityBundle.from_private_bundle(private_data)
    except Exception:
        log.exception("Failed to load identity bundle")
        return None


def _ensure_keystore(password: str) -> Optional[StateStore]:
    """Open the keystore with the given password; caches on success."""
    global _keystore_store, _keystore_password
    if _keystore_store is not None and password == _keystore_password:
        return _keystore_store
    try:
        store = StateStore.load(KEYSTORE_DIR, password)
        store.load_state("identity")   # validate password
        _keystore_store = store
        _keystore_password = password
        return store
    except (FileNotFoundError, InvalidTag, Exception):
        return None


# ── RPC Handlers ──────────────────────────────────────────────────────────────

async def handle_unlock_keystore(params: dict) -> dict:
    """
    Unlock the local encrypted keystore with the user's password.
    Must succeed before encrypt/decrypt or session operations can run.
    """
    password = params.get("password") or params.get("keystore_password", "")
    if not password:
        return {"success": False, "error": "password required."}
    try:
        store = await asyncio.to_thread(_ensure_keystore, password)
        if store is None:
            return {"success": False, "error": "Invalid password or no keystore found."}
        return {"success": True}
    except Exception:
        log.exception("unlock_keystore failed")
        return {"success": False, "error": "Internal server error."}


async def handle_generate_identity_bundle(params: dict) -> dict:
    """
    Generate a fresh PQXDH identity bundle, derive SRP credentials from the
    password, sign the server-issued nonce, and return everything the server's
    POST /auth/register endpoint expects in its `bundle` field.
    """
    global _keystore_store, _keystore_password

    password = params.get("password") or params.get("keystore_password", "")
    username = params.get("username", "local")
    nonce    = params.get("nonce", "")

    if not password:
        return {"error": "password required."}
    if not nonce or len(nonce) != 64:
        return {"error": "nonce must be a 64-char hex string."}

    try:
        async with _registration_lock:
            if KEYSTORE_DIR.exists():
                try:
                    existing = await asyncio.to_thread(StateStore.load, KEYSTORE_DIR, password)
                    existing.load_state("identity")
                except InvalidTag:
                    return {"error": "Wrong password — cannot overwrite existing keystore."}
                shutil.rmtree(KEYSTORE_DIR)

            bundle: IdentityBundle = await asyncio.to_thread(_gen_bundle, username)
            store = await asyncio.to_thread(StateStore.create, KEYSTORE_DIR, password)
            store.save_state("identity", bundle.to_private_bundle())

            _keystore_store  = store
            _keystore_password = password

        # Generate SRP verifier — same group parameters as the server.
        nonce_bytes = bytes.fromhex(nonce)
        salt, verifier = await asyncio.to_thread(
            _srp_lib.create_salted_verification_key,
            username, password,
            salt_len=32,
            **_SRP_3072_KWARGS,
        )
        srp_salt_hex     = salt.hex().zfill(64)      # pad to 64 hex chars (32 bytes)
        srp_verifier_hex = verifier.hex().zfill(768)  # pad to 768 hex chars (384 bytes)

        # Sign the server nonce — proof-of-possession of the signing key.
        nonce_signature = bundle.ik_sig.sign(nonce_bytes)

        # Return in the exact format POST /auth/register expects.
        return {
            "srp_salt":               srp_salt_hex,
            "srp_verifier":           srp_verifier_hex,
            "idk_classical_pub":      bundle.ik_classical.public_key_bytes.hex(),
            "idk_pq_pub":             bundle.ik_kem.public_key.hex(),
            "identity_signing_pub":   bundle.ik_sig.public_key.hex(),
            "signed_prekey_pub":      bundle.spk.keypair.public_key_bytes.hex(),
            "signed_prekey_signature": bundle.spk.signature.hex(),
            "nonce":                  nonce,
            "nonce_signature":        nonce_signature.hex(),
            "device_name":            None,
        }
    except Exception:
        log.exception("generate_identity_bundle failed")
        return {"error": "Internal server error."}


async def handle_srp_start(params: dict) -> dict:
    """
    SRP round 0 (client side): initialise a new SRP session and return A.
    Must be called before srp_challenge.
    """
    global _srp_session

    username = params.get("username", "")
    password = params.get("password", "")
    if not username or not password:
        return {"error": "username and password required."}
    try:
        _srp_session = SrpSession(username, password)
        return {"A": _srp_session.A_hex}
    except Exception:
        log.exception("srp_start failed")
        return {"error": "SRP initialisation failed."}


async def handle_srp_challenge(params: dict) -> dict:
    """
    SRP round 1 (client side): process the server's salt + B ephemeral and
    return M1 (client session proof).
    """
    if _srp_session is None:
        return {"error": "Call srp_start first."}
    salt = params.get("salt", "")
    B    = params.get("B", "")
    if not salt or not B:
        return {"error": "salt and B required."}
    try:
        M1 = await asyncio.to_thread(_srp_session.process_challenge, salt, B)
        return {"M1": M1}
    except Exception as exc:
        log.exception("srp_challenge failed")
        return {"error": str(exc)}


async def handle_srp_verify(params: dict) -> dict:
    """
    SRP round 2 (client side): verify the server's M2 proof (mutual auth).
    On success, returns the session key so the client can send it as a Bearer
    token in subsequent API calls.
    """
    if _srp_session is None:
        return {"authenticated": False, "error": "Call srp_start first."}
    M2 = params.get("M2", "")
    if not M2:
        return {"authenticated": False, "error": "M2 required."}
    try:
        ok = await asyncio.to_thread(_srp_session.verify_server, M2)
        if not ok:
            return {"authenticated": False, "error": "Server authentication failed."}
        # The session key K is what the server stores — the client sends it as Bearer.
        K = _srp_session._user.get_session_key()
        return {"authenticated": True, "session_key": K.hex()}
    except Exception:
        log.exception("srp_verify failed")
        return {"authenticated": False, "error": "Verification failed."}


async def handle_initiate_session(params: dict) -> dict:
    """
    Run PQXDH as the initiator (Alice).

    Takes the remote user's public bundle (as returned by GET /keys/:username),
    derives a 32-byte shared secret SK via hybrid X3DH + ML-KEM-1024, and stores
    it keyed by conversation_id.  The PQXDH initiation bundle (needed by the
    responder) is held for inclusion in the first encrypt_message call.
    """
    conversation_id   = params.get("conversation_id", "")
    remote_bundle_str = params.get("remote_bundle", "")
    if not conversation_id or not remote_bundle_str:
        return {"success": False, "error": "conversation_id and remote_bundle required."}

    # Don't overwrite an existing live session.
    if conversation_id in _session_keys:
        return {"success": True, "already_established": True}

    local_bundle = _load_identity()
    if local_bundle is None:
        return {"success": False, "error": "Keystore not unlocked. Call unlock_keystore first."}

    try:
        remote_bundle = json.loads(remote_bundle_str) if isinstance(remote_bundle_str, str) else remote_bundle_str

        result = await asyncio.to_thread(
            pqxdh_initiate, local_bundle, remote_bundle, True  # allow_no_opk=True
        )
        _session_keys[conversation_id]             = result.SK
        _pending_initiation_bundles[conversation_id] = result.bundle.to_dict()
        return {"success": True}
    except Exception:
        log.exception("initiate_session failed")
        return {"success": False, "error": "PQXDH initiation failed."}


async def handle_respond_session(params: dict) -> dict:
    """
    Run PQXDH as the responder (Bob).

    Called internally by decrypt_message when it detects an initiation_bundle
    in an incoming envelope.  Can also be called explicitly.
    """
    conversation_id     = params.get("conversation_id", "")
    initiation_bundle_d = params.get("initiation_bundle", {})
    if not conversation_id or not initiation_bundle_d:
        return {"success": False, "error": "conversation_id and initiation_bundle required."}

    if conversation_id in _session_keys:
        return {"success": True, "already_established": True}

    local_bundle = _load_identity()
    if local_bundle is None:
        return {"success": False, "error": "Keystore not unlocked."}

    try:
        from core.pqxdh import InitiationBundle
        initiation = InitiationBundle.from_dict(initiation_bundle_d)
        # allow_no_opk path: responder uses identity KEM key when used_identity_kem=True
        result = await asyncio.to_thread(
            pqxdh_respond, local_bundle, initiation, {}, {}
        )
        _session_keys[conversation_id] = result.SK
        return {"success": True}
    except Exception:
        log.exception("respond_session failed")
        return {"success": False, "error": "PQXDH response failed."}


async def handle_encrypt_message(params: dict) -> dict:
    """
    Encrypt a plaintext message with ChaCha20-Poly1305 using the conversation's
    PQXDH-derived shared secret.

    On the first call for a conversation the PQXDH initiation bundle is
    included in the response so the server can relay it to the recipient.
    """
    conversation_id = params.get("conversation_id", "")
    plaintext       = params.get("plaintext", "")
    if not conversation_id:
        return {"error": "conversation_id required."}
    if not plaintext:
        return {"error": "plaintext required."}

    sk = _session_keys.get(conversation_id)
    if sk is None:
        return {"error": "NO_SESSION: call initiate_session first for this conversation."}

    try:
        nonce = os.urandom(12)
        aad   = conversation_id.encode()
        ct    = ChaCha20Poly1305(sk).encrypt(nonce, plaintext.encode(), aad)

        initiation_bundle = _pending_initiation_bundles.pop(conversation_id, None)

        return {
            "ciphertext":        ct.hex(),
            "nonce":             nonce.hex(),
            "conversation_id":   conversation_id,
            "initiation_bundle": initiation_bundle,
        }
    except Exception:
        log.exception("encrypt_message failed")
        return {"error": "Encryption failed."}


async def handle_decrypt_message(params: dict) -> dict:
    """
    Decrypt an incoming message envelope.

    If the envelope contains an initiation_bundle and no session exists yet,
    automatically runs the PQXDH responder path to derive SK before decrypting.
    """
    envelope        = params.get("envelope", {})
    conversation_id = envelope.get("conversation_id", "")
    ciphertext_hex  = envelope.get("ciphertext", "")
    nonce_hex       = envelope.get("nonce", "")
    initiation_bundle = envelope.get("initiation_bundle")

    if not conversation_id or not ciphertext_hex or not nonce_hex:
        return {"error": "envelope must contain conversation_id, ciphertext, and nonce."}

    # Auto-respond to PQXDH if this is the first message in the conversation.
    if conversation_id not in _session_keys and initiation_bundle:
        local_bundle = _load_identity()
        if local_bundle is None:
            return {"error": "Keystore not unlocked."}
        try:
            from core.pqxdh import InitiationBundle
            initiation = InitiationBundle.from_dict(initiation_bundle)
            result = await asyncio.to_thread(
                pqxdh_respond, local_bundle, initiation, {}, {}
            )
            _session_keys[conversation_id] = result.SK
        except Exception:
            log.exception("Auto-respond PQXDH failed")
            return {"error": "Session establishment failed — cannot decrypt."}

    sk = _session_keys.get(conversation_id)
    if sk is None:
        return {"error": "NO_SESSION: no established session for this conversation."}

    try:
        nonce = bytes.fromhex(nonce_hex)
        ct    = bytes.fromhex(ciphertext_hex)
        aad   = conversation_id.encode()
        plaintext = ChaCha20Poly1305(sk).decrypt(nonce, ct, aad)
        return {"plaintext": plaintext.decode("utf-8", errors="replace")}
    except InvalidTag:
        return {"error": "Decryption failed: authentication tag mismatch."}
    except Exception:
        log.exception("decrypt_message failed")
        return {"error": "Decryption failed."}


HANDLERS = {
    "unlock_keystore":           handle_unlock_keystore,
    "generate_identity_bundle":  handle_generate_identity_bundle,
    "srp_start":                 handle_srp_start,
    "srp_challenge":             handle_srp_challenge,
    "srp_verify":                handle_srp_verify,
    "initiate_session":          handle_initiate_session,
    "respond_session":           handle_respond_session,
    "encrypt_message":           handle_encrypt_message,
    "decrypt_message":           handle_decrypt_message,
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

            req_id = request.get("id")
            method = request.get("method", "")
            params = request.get("params", {})

            handler = HANDLERS.get(method)
            if handler is None:
                response = {"error": f"Unknown method: {method!r}"}
            else:
                response = await handler(params)

            response = {**response, "id": req_id}
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
