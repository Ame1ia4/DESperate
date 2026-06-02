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

from core.keys import (
    generate_identity_bundle as _gen_bundle,
    IdentityBundle,
)
from core.password import derive_master_components
from core.srp_session import SrpSession
from core.pqxdh import (
    initiate  as _pqxdh_initiate,
    respond   as _pqxdh_respond,
    InitiationBundle,
    MalformedBundleError,
    SPKVerificationError,
)
from core.dh_ratchet.session import RatchetSession
from core.state_store import StateStore
from cryptography.exceptions import InvalidTag
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

_srp_session:        Optional[SrpSession]    = None
_store:              Optional[StateStore]    = None
_local_bundle:       Optional[IdentityBundle] = None
_cached_srp_pass:    Optional[bytes]         = None   # derived by unlock_keystore; reused by srp_start
_cached_keystore_key: Optional[bytes]        = None   # retained for future rekey operations


@dataclass
class _SessionEntry:
    ratchet:           RatchetSession
    remote_ik_sig_pub: bytes
    init_bundle:       Optional[dict]   # included once with first sent message, then cleared


_sessions: dict[str, _SessionEntry] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _create_srp_verifier(username: str, password: str) -> tuple[bytes, bytes]:
    """
    Derive SRP salt + verifier using the same formula as SrpSession.process_challenge.

    pysrp.create_salted_verification_key uses salt_len=4 (4 bytes) by default and
    stores the salt as a variable-length BigInteger. Sending that zero-padded to 64
    hex chars and then decoding it back produces a 32-byte salt that differs from the
    4-byte salt pysrp used to compute x — causing x (and thus M1) to never match.

    We generate the salt ourselves (always exactly 32 bytes) and compute v directly,
    so registration and login use identical byte sequences.
    """
    from core.srp_session import _sha256, _N, _g, _N_BYTES
    salt = os.urandom(32)
    x = int.from_bytes(
        _sha256(salt, _sha256((username + ":" + password).encode())),
        "big",
    )
    v = pow(_g, x, _N)
    verifier = v.to_bytes(_N_BYTES, "big")
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


def _load_master_salt() -> Optional[bytes]:
    """Return the persisted Argon2id salt, or None if no keystore exists yet."""
    salt_path = _STORE_BASE_DIR / "salt"
    return salt_path.read_bytes() if salt_path.exists() else None


# ── RPC handlers ──────────────────────────────────────────────────────────────

def _handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
    global _srp_session, _store, _local_bundle, _cached_srp_pass, _cached_keystore_key

    # ── Keystore ──────────────────────────────────────────────────────────────

    if method == "unlock_keystore":
        password = params.get("password", "")
        if not password:
            return {"success": False, "error": "Password required"}

        master_salt = _load_master_salt()
        if master_salt is None:
            # No keystore yet — bootstrap an empty store (rare: called before registration).
            srp_pass, keystore_key, master_salt = derive_master_components(password)
            _store = StateStore.create_with_key(_STORE_BASE_DIR, keystore_key, master_salt)
        else:
            srp_pass, keystore_key, _ = derive_master_components(password, master_salt)
            _store = StateStore.load_with_key(_STORE_BASE_DIR, keystore_key)

        _cached_srp_pass    = srp_pass
        _cached_keystore_key = keystore_key

        # Load identity bundle if one has been persisted from a previous registration.
        # InvalidTag here means the derived keystore_key is wrong (wrong password).
        if _store.state_exists(_BUNDLE_KEY):
            try:
                raw = _store.load_state(_BUNDLE_KEY)
                _local_bundle = IdentityBundle.from_private_bundle(raw)
            except InvalidTag:
                _store = None
                _cached_srp_pass    = None
                _cached_keystore_key = None
                return {"success": False, "error": "Wrong password"}

        return {"success": True}

    # ── Key bundle generation (registration) ──────────────────────────────────

    if method == "generate_identity_bundle":
        username  = params["username"]
        password  = params["password"]
        nonce_hex = params["nonce"]

        # Derive SRP synthetic password and keystore encryption key from one Argon2id call.
        srp_pass, keystore_key, master_salt = derive_master_components(password)
        _cached_srp_pass    = srp_pass
        _cached_keystore_key = keystore_key

        bundle = _gen_bundle(user_id=username)

        # The bundle's ik_sig is a hybrid Ed25519 + ML-DSA-87 keypair.
        # Its public_key is already the 2624-byte composite (ed25519_pub || ml_dsa_pub)
        # that the server expects as identity_signing_pub.
        identity_signing_pub = bundle.ik_sig.public_key          # 2624 bytes

        nonce_bytes = bytes.fromhex(nonce_hex)
        nonce_sig   = bundle.ik_sig.sign(nonce_bytes)             # 4691 bytes
        spk_sig     = bundle.ik_sig.sign(bundle.spk.keypair.public_key_bytes)  # 4691 bytes

        # SRP verifier is computed from the derived srp_pass (hex), NOT the raw password.
        # This matches what srp_start does on every subsequent login.
        salt_bytes, verifier_bytes = _create_srp_verifier(username, srp_pass.hex())

        # Persist the private bundle encrypted under keystore_key.
        if _store is None:
            if (_STORE_BASE_DIR / "salt").exists():
                # Salt file was written by a previous registration attempt that crashed
                # before save_state completed. Reuse the existing store rather than
                # failing with FileExistsError.
                _store = StateStore.load_with_key(_STORE_BASE_DIR, keystore_key)
            else:
                _store = StateStore.create_with_key(_STORE_BASE_DIR, keystore_key, master_salt)
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
        # Discard any stale session from a previous incomplete flow.
        _srp_session = None

        # Prefer the srp_pass cached by unlock_keystore to avoid running Argon2id twice.
        # Fall back to re-deriving if srp_start is called without a prior unlock
        # (e.g. the keystore doesn't exist yet on a fresh device).
        if _cached_srp_pass is not None:
            srp_pass = _cached_srp_pass
        else:
            master_salt = _load_master_salt()
            srp_pass, keystore_key, _ = derive_master_components(
                params["password"], master_salt
            )
            _cached_srp_pass    = srp_pass
            _cached_keystore_key = keystore_key

        _srp_session = SrpSession(params["username"], srp_pass.hex())
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
        # K is returned so the C++ client can verify mutual auth succeeded,
        # but it is NOT used as the Bearer token — the server-issued HKDF
        # session_token (from /auth/login) is used instead.
        session_key = _srp_session.session_key_hex if authenticated else None
        _srp_session = None
        # srp_pass is no longer needed once authentication completes — clear it to
        # reduce the window during which it lives in process memory.
        _cached_srp_pass = None
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

        # Resolve which key to verify against. The stored pin is authoritative;
        # a caller-supplied key is only accepted when the pin is not yet set
        # (first message on a session restored from disk with no prior contact).
        # After the pin is set it is never overridden by the caller — that would
        # allow a compromised server to substitute a rogue key mid-conversation.
        if entry.remote_ik_sig_pub:
            sig_pub = entry.remote_ik_sig_pub
        elif sender_ik_sig_pub_hex:
            sig_pub = bytes.fromhex(sender_ik_sig_pub_hex)
            # Pin this key for all subsequent messages.
            entry.remote_ik_sig_pub = sig_pub
            store = _require_store()
            store.save_state(
                f"{_META_KEY_PREFIX}{conversation_id}",
                {"remote_ik_sig_pub": sig_pub.hex()},
            )
        else:
            raise ValueError("sender_ik_sig_pub is required to verify message signatures")

        try:
            signed = verify_and_extract(
                data=payload, aad=aad,
                ik_sig_pub=sig_pub, expected_pub=entry.remote_ik_sig_pub,
            )
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
