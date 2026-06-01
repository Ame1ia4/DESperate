"""
crypto_service.py — Local cryptography microservice for the DESperate client.

Listens on TCP 127.0.0.1:54231 for newline-delimited JSON-RPC requests.

Protocol:
  Request:  {"id": "...", "method": "...", "params": {...}}\n
  Success:  {"id": "...", ...result_fields...}\n
  Failure:  {"id": "...", "error": "message"}\n

Methods:
  unlock_keystore          — derive encryption key from passphrase, load identity bundle
  generate_identity_bundle — generate and persist PQXDH keys for registration
  srp_start                — begin SRP-6a login (round 1)
  srp_challenge            — process server SRP challenge (round 2)
  srp_verify               — verify server proof, return SRP session key K
  initiate_session         — run PQXDH as initiator, seed Double Ratchet
  encrypt_message          — Double Ratchet encrypt + hybrid Ed25519/ML-DSA-87 sign
  decrypt_message          — hybrid verify + Double Ratchet decrypt; auto-responds to PQXDH

Compile to a standalone binary with PyInstaller:
  pyinstaller --onedir --name crypto_service crypto_service.py
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import srp as _srp

from core.keys import (
    generate_identity_bundle as _gen_bundle,
    IdentityBundle,
)
from core.srp_session import SrpSession, _SRP_3072_KWARGS
from core.pqxdh import (
    initiate  as _pqxdh_initiate,
    respond   as _pqxdh_respond,
    InitiationBundle,
    MalformedBundleError,
    SPKVerificationError,
)
from core.dh_ratchet.session import RatchetSession
from core.state_store import StateStore
from core.signatures import (
    sign_ciphertext,
    verify_and_extract,
    SignatureVerificationError,
)

HOST = "127.0.0.1"
PORT = 54231

# ── Keystore ──────────────────────────────────────────────────────────────────

_STORE_BASE_DIR  = Path.home() / ".desperate_keys"
_BUNDLE_KEY      = "__identity__"     # StateStore session_id for identity bundle
_META_KEY_PREFIX = "__sigmeta__"      # prefix for per-session sig-pub storage

# ── Event loop (bridges async Double Ratchet code into sync RPC dispatch) ────

_loop = asyncio.new_event_loop()


def _run(coro: Any) -> Any:
    """Run a coroutine to completion on the module-level event loop."""
    return _loop.run_until_complete(coro)


# ── Module-level state ────────────────────────────────────────────────────────

_srp_session:  Optional[SrpSession]   = None
_store:        Optional[StateStore]   = None
_local_bundle: Optional[IdentityBundle] = None


@dataclass
class _SessionEntry:
    ratchet:           RatchetSession
    remote_ik_sig_pub: bytes
    init_bundle:       Optional[dict]   # included once with first sent message, then cleared


_sessions: dict[str, _SessionEntry] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _create_srp_verifier(username: str, password: str) -> tuple[bytes, bytes]:
    """Derive SRP salt + verifier via pysrp (NG_3072, SHA-256)."""
    salt, verifier = _srp.create_salted_verification_key(
        username, password, **_SRP_3072_KWARGS
    )
    return salt, verifier


def _require_store() -> StateStore:
    if _store is None:
        raise ValueError("Keystore not unlocked — call unlock_keystore first")
    return _store


def _require_bundle() -> IdentityBundle:
    if _local_bundle is None:
        raise ValueError("Identity bundle unavailable — call unlock_keystore or generate_identity_bundle first")
    return _local_bundle


def _require_session(conversation_id: str) -> _SessionEntry:
    entry = _sessions.get(conversation_id)
    if entry is not None:
        return entry
    # Try restoring from disk (survives Python service restart within the same keystore).
    store = _require_store()
    meta_key = f"{_META_KEY_PREFIX}{conversation_id}"
    if store.state_exists(conversation_id) and store.state_exists(meta_key):
        meta          = store.load_state(meta_key)
        ratchet       = _run(RatchetSession.load(store, conversation_id))
        sig_pub_bytes = bytes.fromhex(meta["remote_ik_sig_pub"])
        entry = _SessionEntry(ratchet=ratchet, remote_ik_sig_pub=sig_pub_bytes, init_bundle=None)
        _sessions[conversation_id] = entry
        return entry
    raise ValueError(
        f"No active session for {conversation_id!r}. Call initiate_session first."
    )


def _open_or_create_store(password: str) -> StateStore:
    """Load an existing StateStore or create a fresh one."""
    salt_path = _STORE_BASE_DIR / "salt"
    if salt_path.exists():
        return StateStore.load(_STORE_BASE_DIR, password)
    return StateStore.create(_STORE_BASE_DIR, password)


# ── RPC handlers ──────────────────────────────────────────────────────────────

def _handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
    global _srp_session, _store, _local_bundle

    # ── Keystore ──────────────────────────────────────────────────────────────

    if method == "unlock_keystore":
        password = params.get("password", "")
        if not password:
            return {"success": False, "error": "Password required"}
        _store = _open_or_create_store(password)
        # Load identity bundle if one has been persisted from a previous registration.
        if _store.state_exists(_BUNDLE_KEY):
            raw = _store.load_state(_BUNDLE_KEY)
            _local_bundle = IdentityBundle.from_private_bundle(raw)
        return {"success": True}

    # ── Key bundle generation (registration) ──────────────────────────────────

    if method == "generate_identity_bundle":
        username  = params["username"]
        password  = params["password"]
        nonce_hex = params["nonce"]

        bundle = _gen_bundle(user_id=username)

        # The bundle's ik_sig is a hybrid Ed25519 + ML-DSA-87 keypair.
        # Its public_key is already the 2624-byte composite (ed25519_pub || ml_dsa_pub)
        # that the server expects as identity_signing_pub.
        identity_signing_pub = bundle.ik_sig.public_key          # 2624 bytes

        nonce_bytes = bytes.fromhex(nonce_hex)
        nonce_sig   = bundle.ik_sig.sign(nonce_bytes)             # 4691 bytes
        spk_sig     = bundle.ik_sig.sign(bundle.spk.keypair.public_key_bytes)  # 4691 bytes

        salt_bytes, verifier_bytes = _create_srp_verifier(username, password)

        # Persist the private bundle so unlock_keystore can restore it on restart.
        # If the keystore wasn't opened first, bootstrap it with this password.
        if _store is None:
            _store = _open_or_create_store(password)
        _store.save_state(_BUNDLE_KEY, bundle.to_private_bundle())
        _local_bundle = bundle

        return {
            "srp_salt":                salt_bytes.hex(),
            "srp_verifier":            verifier_bytes.hex(),
            "idk_classical_pub":       bundle.ik_classical.public_key_bytes.hex(),
            "idk_pq_pub":              bundle.ik_kem.public_key.hex(),
            "identity_signing_pub":    identity_signing_pub.hex(),
            "signed_prekey_pub":       bundle.spk.keypair.public_key_bytes.hex(),
            "signed_prekey_signature": spk_sig.hex(),
            "nonce":                   nonce_hex,
            "nonce_signature":         nonce_sig.hex(),
        }

    # ── SRP authentication ─────────────────────────────────────────────────────

    if method == "srp_start":
        _srp_session = SrpSession(params["username"], params["password"])
        return {"A": _srp_session.A_hex}

    if method == "srp_challenge":
        if _srp_session is None:
            raise ValueError("No SRP session active — call srp_start first")
        M1 = _srp_session.process_challenge(params["salt"], params["B"])
        return {"M1": M1}

    if method == "srp_verify":
        if _srp_session is None:
            raise ValueError("No SRP session active — call srp_start first")
        authenticated = _srp_session.verify_server(params["M2"])
        # The SRP session key K is the same value the server stored via storeSessionKey.
        # Return it so the C++ client can send it as the Authorization: Bearer token.
        session_key = _srp_session.session_key_hex if authenticated else None
        _srp_session = None
        return {"authenticated": authenticated, "session_key": session_key}

    # ── Session initiation (PQXDH → Double Ratchet) ───────────────────────────

    if method == "initiate_session":
        conversation_id = params["conversation_id"]
        remote_bundle   = params["remote_bundle"]   # dict from GET /keys/:username

        bundle = _require_bundle()
        store  = _require_store()

        try:
            result = _pqxdh_initiate(bundle, remote_bundle, allow_no_opk=True)
        except SPKVerificationError as exc:
            raise ValueError(f"SPK verification failed — possible MITM: {exc}") from exc
        except MalformedBundleError as exc:
            raise ValueError(f"Malformed remote bundle: {exc}") from exc

        # Bob's SPK is his initial Double Ratchet public key (Signal PQXDH spec §4).
        bob_ratchet_pub = bytes.fromhex(remote_bundle["spk_pub"])

        ratchet = _run(
            RatchetSession.create_as_initiator(
                SK              = result.SK,
                bob_ratchet_pub = bob_ratchet_pub,
                store           = store,
                session_id      = conversation_id,
            )
        )

        # Persist remote signing public key for later message signature verification.
        remote_sig_pub = bytes.fromhex(remote_bundle["ik_sig_pub"])
        store.save_state(
            f"{_META_KEY_PREFIX}{conversation_id}",
            {"remote_ik_sig_pub": remote_sig_pub.hex()},
        )

        init_bundle_dict = result.bundle.to_dict() if result.bundle else None
        _sessions[conversation_id] = _SessionEntry(
            ratchet           = ratchet,
            remote_ik_sig_pub = remote_sig_pub,
            init_bundle       = init_bundle_dict,
        )

        return {"success": True, "initiation_bundle": init_bundle_dict}

    # ── Message encryption (Double Ratchet + hybrid signature) ────────────────

    if method == "encrypt_message":
        conversation_id    = params["conversation_id"]
        plaintext_str      = params["plaintext"]
        recipient_username = params.get("recipient_username", "")

        entry  = _require_session(conversation_id)
        bundle = _require_bundle()

        plaintext = plaintext_str.encode("utf-8")
        aad       = conversation_id.encode("utf-8")

        # Double Ratchet encrypt — advances the ratchet and persists state atomically.
        wire_bytes = _run(entry.ratchet.encrypt(plaintext, aad))

        # Sign the wire-format ciphertext with the sender's hybrid keypair.
        # Prevents server-injected ciphertexts from being accepted by the recipient.
        sender_id    = bundle.user_id.encode("utf-8")
        recipient_id = recipient_username.encode("utf-8")
        signed = sign_ciphertext(
            signing_keypair = bundle.ik_sig,
            ciphertext      = wire_bytes,
            aad             = aad,
            sender_id       = sender_id,
            recipient_id    = recipient_id,
            message_index   = entry.ratchet.message_index,
        )
        payload = signed.to_bytes()   # msgpack-encoded signed ciphertext

        # The server schema requires a 12-byte nonce field alongside the ciphertext.
        # We use the first 12 bytes of the wire header (version + msg_index + pn),
        # which are strictly unique per message within this session.
        nonce_bytes = wire_bytes[:12]

        # The PQXDH initiation bundle is included with the first message only.
        init_bundle       = entry.init_bundle
        entry.init_bundle = None   # clear after first use

        return {
            "ciphertext":        payload.hex(),
            "nonce":             nonce_bytes.hex(),
            "initiation_bundle": init_bundle,
        }

    # ── Message decryption (hybrid verify + Double Ratchet) ───────────────────

    if method == "decrypt_message":
        conversation_id       = params["conversation_id"]
        ciphertext_hex        = params["ciphertext"]
        initiation_bundle     = params.get("initiation_bundle")       # dict or None
        sender_ik_sig_pub_hex = params.get("sender_ik_sig_pub", "")   # hex or ""

        bundle = _require_bundle()
        store  = _require_store()

        payload = bytes.fromhex(ciphertext_hex)
        aad     = conversation_id.encode("utf-8")

        # If we have no session yet and the message carries an initiation bundle,
        # respond to PQXDH and create the ratchet session as the responder (Bob).
        if conversation_id not in _sessions:
            if not initiation_bundle:
                raise ValueError(
                    f"No session for {conversation_id!r} and no initiation_bundle — "
                    "cannot decrypt first message."
                )
            init = InitiationBundle.from_dict(initiation_bundle)

            # OPK secret keys are not yet stored locally (OPK replenishment stub).
            # The initiator uses allow_no_opk=True, so used_identity_kem=True and
            # opk_id=None — the respond() call needs no local OPK secret keys.
            pqxdh_result = _pqxdh_respond(
                local_bundle      = bundle,
                initiation        = init,
                local_x25519_opks = {},
                local_kem_opks    = {},
            )

            ratchet = _run(
                RatchetSession.create_as_responder(
                    SK         = pqxdh_result.SK,
                    store      = store,
                    session_id = conversation_id,
                )
            )

            remote_sig_pub = bytes.fromhex(sender_ik_sig_pub_hex) if sender_ik_sig_pub_hex else b""
            store.save_state(
                f"{_META_KEY_PREFIX}{conversation_id}",
                {"remote_ik_sig_pub": remote_sig_pub.hex()},
            )
            _sessions[conversation_id] = _SessionEntry(
                ratchet           = ratchet,
                remote_ik_sig_pub = remote_sig_pub,
                init_bundle       = None,
            )

        entry = _sessions[conversation_id]

        # Use the caller-supplied sig pub if provided (refreshes on each message
        # so key rotation is handled transparently); fall back to stored value.
        sig_pub = (
            bytes.fromhex(sender_ik_sig_pub_hex)
            if sender_ik_sig_pub_hex
            else entry.remote_ik_sig_pub
        )

        if not sig_pub:
            raise ValueError("sender_ik_sig_pub is required to verify message signatures")

        try:
            signed = verify_and_extract(data=payload, aad=aad, ik_sig_pub=sig_pub)
        except SignatureVerificationError as exc:
            raise ValueError(f"Message signature verification failed: {exc}") from exc

        plaintext = _run(entry.ratchet.decrypt(signed, aad))

        return {"plaintext": plaintext.decode("utf-8", errors="replace")}

    raise ValueError(f"Unknown method: {method!r}")


# ── TCP server ────────────────────────────────────────────────────────────────

def _process_line(line: bytes) -> bytes:
    req_id = None
    try:
        req    = json.loads(line.decode("utf-8"))
        req_id = req.get("id")
        result = _handle(req["method"], req.get("params") or {})
        resp   = {"id": req_id, **result}
    except Exception as exc:
        resp = {"id": req_id, "error": str(exc)}
    return (json.dumps(resp) + "\n").encode("utf-8")


def _serve_connection(conn: socket.socket) -> None:
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    conn.sendall(_process_line(line))
    finally:
        conn.close()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        while True:
            conn, _ = srv.accept()
            _serve_connection(conn)


if __name__ == "__main__":
    main()
