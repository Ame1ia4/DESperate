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

# M1 fix: Unix domain socket replaces TCP so the OS enforces that only
# processes owned by the same UID can connect. No port is exposed at all,
# eliminating the local network attack surface entirely.
SOCKET_PATH = Path.home() / ".desperate_keys" / "crypto.sock"

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

_srp_session:    Optional[SrpSession]   = None
_store:          Optional[StateStore]   = None
_local_bundle:   Optional[IdentityBundle] = None
_pending_sessions: dict = {}   # conversation_id → pending PQXDH state (pre-first-message)


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


def _load_opk_secrets(
    bundle: IdentityBundle,
) -> tuple[dict[int, bytes], dict[int, bytes]]:
    """
    Extract OPK secret key maps from a loaded IdentityBundle.

    Returns (local_x25519_opks, local_kem_opks) as {opk_id: secret_key_bytes}
    dicts suitable for passing directly to pqxdh.respond().

    H3 fix: previously both dicts were always passed as {} to respond(),
    meaning any session initiated with a real OPK (used_identity_kem=False)
    would raise PQXDHError because the secret key was not in the map.
    OPK-based PQ forward secrecy was therefore never actually delivered.
    """
    x25519_map = {opk.opk_id: opk.secret_key for opk in bundle.x25519_opks}
    kem_map    = {opk.opk_id: opk.secret_key for opk in bundle.kem_opks}
    return x25519_map, kem_map


def _consume_opk(
    store:  StateStore,
    bundle: IdentityBundle,
    opk_id: int,
) -> None:
    """
    Remove a consumed OPK pair from the local keystore.

    Called after a successful respond() that used a real OPK so that the
    same secret key is never reused across session resets.
    """
    bundle.x25519_opks = [o for o in bundle.x25519_opks if o.opk_id != opk_id]
    bundle.kem_opks    = [o for o in bundle.kem_opks    if o.opk_id != opk_id]
    store.save_state(_BUNDLE_KEY, bundle.to_private_bundle())


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
        # M1 fix: unlock must ONLY open an existing keystore, never create one.
        # Previously _open_or_create_store would silently create a fresh keystore
        # with an attacker-supplied password if the directory did not exist,
        # allowing a local process to replace the real keystore before the
        # legitimate user unlocked it. Use StateStore.load() directly instead.
        salt_path = _STORE_BASE_DIR / "salt"
        if not salt_path.exists():
            return {
                "success": False,
                "error": "No keystore found. Register first.",
            }
        _store = StateStore.load(_STORE_BASE_DIR, password)
        # Load identity bundle if one has been persisted from a previous registration.
        if _store.state_exists(_BUNDLE_KEY):
            try:
                raw = _store.load_state(_BUNDLE_KEY)
                _local_bundle = IdentityBundle.from_private_bundle(raw)
            except InvalidTag:
                _store = None
                return {
                    "success": False,
                    "error": (
                        f"Wrong password — could not decrypt keystore at {_STORE_BASE_DIR}. "
                        "If you re-registered, delete that directory and log in again."
                    ),
                }
        else:
            # Keystore exists (password is correct) but the identity bundle was never
            # saved — this happens when the keystore directory was deleted after
            # registration and then a new (empty) keystore was created by a later run.
            _store = None
            return {
                "success": False,
                "error": (
                    f"Identity keys not found in keystore at {_STORE_BASE_DIR}. "
                    "Your local keys were lost. Delete that directory and re-register."
                ),
            }
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
            # If an existing keystore was loaded, verify the password by attempting
            # a test decrypt.  If it fails, the user registered previously with a
            # different password and we must not silently overwrite with the wrong key.
            if _store is not None:
                try:
                    _store.load_state(_BUNDLE_KEY)
                except FileNotFoundError:
                    pass  # first-time registration — no bundle persisted yet, fine
                except InvalidTag:
                    _store = None
                    raise ValueError(
                        "Keystore exists but password is wrong — delete "
                        f"{_STORE_BASE_DIR} to start fresh, or use the original password."
                    )
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
        # K is returned so the C++ client can verify mutual auth succeeded,
        # but it is NOT used as the Bearer token — the server-issued HKDF
        # session_token (from /auth/login) is used instead.
        session_key = _srp_session.session_key_hex if authenticated else None
        _srp_session = None
        return {"authenticated": authenticated, "session_key": session_key}

    # ── Session existence check ───────────────────────────────────────────────

    if method == "has_session":
        conversation_id = params["conversation_id"]
        if conversation_id in _sessions or conversation_id in _pending_sessions:
            return {"exists": True}
        try:
            store    = _require_store()
            meta_key = f"{_META_KEY_PREFIX}{conversation_id}"
            exists   = store.state_exists(conversation_id) and store.state_exists(meta_key)
        except Exception:
            exists = False
        return {"exists": exists}

    # ── Session initiation (PQXDH → Double Ratchet) ───────────────────────────

    if method == "initiate_session":
        conversation_id = params["conversation_id"]
        remote_bundle   = params["remote_bundle"]   # dict from GET /keys/:username
        if isinstance(remote_bundle, str):
            remote_bundle = json.loads(remote_bundle)

        bundle = _require_bundle()

        try:
            result = _pqxdh_initiate(bundle, remote_bundle, allow_no_opk=True)
        except SPKVerificationError as exc:
            raise ValueError(f"SPK verification failed — possible MITM: {exc}") from exc
        except MalformedBundleError as exc:
            raise ValueError(f"Malformed remote bundle: {exc}") from exc

        bob_ratchet_pub  = bytes.fromhex(remote_bundle["spk_pub"])
        remote_sig_pub   = bytes.fromhex(remote_bundle["ik_sig_pub"])
        init_bundle_dict = result.bundle.to_dict() if result.bundle else None

        # Defer Double Ratchet creation until the first encrypt_message call —
        # python-doubleratchet >=1.0 requires the first plaintext to be bundled
        # with encrypt_initial_message, so we can't create the ratchet here.
        _pending_sessions[conversation_id] = {
            "SK":             result.SK,
            "bob_ratchet_pub": bob_ratchet_pub,
            "remote_sig_pub":  remote_sig_pub,
            "init_bundle":     init_bundle_dict,
        }

        return {"success": True, "initiation_bundle": init_bundle_dict}

    # ── Message encryption (Double Ratchet + hybrid signature) ────────────────

    if method == "encrypt_message":
        conversation_id    = params["conversation_id"]
        plaintext_str      = params["plaintext"]
        recipient_username = params.get("recipient_username", "")

        bundle    = _require_bundle()
        plaintext = plaintext_str.encode("utf-8")
        aad       = conversation_id.encode("utf-8")

        if conversation_id in _pending_sessions:
            # First message: create the Double Ratchet session and encrypt together.
            pending = _pending_sessions.pop(conversation_id)
            store   = _require_store()

            session, wire_bytes = _run(
                RatchetSession.create_as_initiator(
                    SK              = pending["SK"],
                    bob_ratchet_pub = pending["bob_ratchet_pub"],
                    plaintext       = plaintext,
                    associated_data = aad,
                    store           = store,
                    session_id      = conversation_id,
                )
            )
            store.save_state(
                f"{_META_KEY_PREFIX}{conversation_id}",
                {"remote_ik_sig_pub": pending["remote_sig_pub"].hex()},
            )
            _sessions[conversation_id] = _SessionEntry(
                ratchet           = session,
                remote_ik_sig_pub = pending["remote_sig_pub"],
                init_bundle       = None,
            )
            init_bundle = pending["init_bundle"]
        else:
            entry      = _require_session(conversation_id)
            wire_bytes = _run(entry.ratchet.encrypt(plaintext, aad))
            init_bundle       = entry.init_bundle
            entry.init_bundle = None

        # Sign the wire-format ciphertext with the sender's hybrid keypair.
        # Prevents server-injected ciphertexts from being accepted by the recipient.
        session_entry = _sessions[conversation_id]
        sender_id     = bundle.user_id.encode("utf-8")
        recipient_id  = recipient_username.encode("utf-8")
        signed = sign_ciphertext(
            signing_keypair = bundle.ik_sig,
            ciphertext      = wire_bytes,
            aad             = aad,
            sender_id       = sender_id,
            recipient_id    = recipient_id,
            message_index   = session_entry.ratchet.message_index,
        )
        payload     = signed.to_bytes()
        nonce_bytes = wire_bytes[:12]

        return {
            "ciphertext":        payload.hex(),
            "nonce":             nonce_bytes.hex(),
            "initiation_bundle": init_bundle,
            "sender_ik_sig_pub": bundle.ik_sig.public_key.hex(),
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

        # An incoming initiation_bundle signals a session reset by the peer —
        # they lost state or re-registered. Before wiping the existing session,
        # save the pinned identity key so we can verify the new session uses the
        # same identity.  A key change is a hard error: it means either the peer
        # genuinely re-registered (they should notify the user out-of-band) or a
        # malicious server is performing a MITM substitution.
        _pinned_ik_before_reset: Optional[bytes] = None
        if initiation_bundle and conversation_id in _sessions:
            _pinned_ik_before_reset = _sessions[conversation_id].remote_ik_sig_pub
            _sessions.pop(conversation_id)
            try:
                store = _require_store()
                store.delete_session(conversation_id)
                store.delete_session(f"{_META_KEY_PREFIX}{conversation_id}")
            except Exception:
                pass

        # Only try disk recovery for subsequent messages (no initiation_bundle).
        # When initiation_bundle is present the peer is establishing a new session
        # — loading an old session from disk would use the wrong ratchet state.
        if conversation_id not in _sessions and not initiation_bundle:
            try:
                _require_session(conversation_id)
            except (ValueError, FileNotFoundError, KeyError, InvalidTag):
                pass

        if conversation_id not in _sessions:
            if not initiation_bundle:
                raise ValueError(
                    f"No session for {conversation_id!r} and no initiation_bundle — "
                    "cannot decrypt first message."
                )
            init = InitiationBundle.from_dict(initiation_bundle)

            # H3 fix: load OPK secret keys from the keystore so respond() can
            # perform DH4 and PQ decapsulation when the initiator used a real OPK
            # (used_identity_kem=False). Previously both maps were always {}, making
            # OPK-based sessions fail and PQ forward secrecy completely absent.
            x25519_opks, kem_opks = _load_opk_secrets(bundle)
            pqxdh_result = _pqxdh_respond(
                local_bundle      = bundle,
                initiation        = init,
                local_x25519_opks = x25519_opks,
                local_kem_opks    = kem_opks,
            )
            # Consume the OPK so the secret key is never reused across resets.
            if init.opk_id is not None and not init.used_identity_kem:
                store = _require_store()
                _consume_opk(store, bundle, init.opk_id)

            # Verify signature first to extract the wire bytes, then use them
            # with create_as_responder (which needs the actual EncryptedMessage).
            remote_sig_pub = bytes.fromhex(sender_ik_sig_pub_hex) if sender_ik_sig_pub_hex else b""
            if not remote_sig_pub:
                raise ValueError("sender_ik_sig_pub required for first message")

            # H1 fix: if this is a re-initiation (we had a prior session), the
            # incoming identity key MUST match the previously pinned key.
            # Any mismatch is treated as a potential MITM key substitution and
            # is rejected hard. The user must verify the new safety number
            # out-of-band before a fresh session can be accepted.
            if _pinned_ik_before_reset is not None:
                if remote_sig_pub != _pinned_ik_before_reset:
                    raise ValueError(
                        "IDENTITY_KEY_CHANGED: peer's identity key does not match the "
                        "previously pinned key for this conversation. This may indicate "
                        "a server MITM or that the peer re-registered. Verify the new "
                        "safety number out-of-band before continuing."
                    )

            try:
                signed_initial = verify_and_extract(
                    data=payload, aad=aad,
                    ik_sig_pub=remote_sig_pub, expected_pub=remote_sig_pub,
                )
            except SignatureVerificationError as exc:
                raise ValueError(f"Message signature verification failed: {exc}") from exc

            # Bob's ratchet private key is his SPK private key.
            own_ratchet_priv = bundle.spk.keypair.private_key_bytes

            session, first_plaintext = _run(
                RatchetSession.create_as_responder(
                    SK               = pqxdh_result.SK,
                    own_ratchet_priv = own_ratchet_priv,
                    wire_bytes       = signed_initial.ciphertext,
                    associated_data  = aad,
                    store            = store,
                    session_id       = conversation_id,
                )
            )

            store.save_state(
                f"{_META_KEY_PREFIX}{conversation_id}",
                {"remote_ik_sig_pub": remote_sig_pub.hex()},
            )
            _sessions[conversation_id] = _SessionEntry(
                ratchet           = session,
                remote_ik_sig_pub = remote_sig_pub,
                init_bundle       = None,
            )

            return {"plaintext": first_plaintext.decode("utf-8", errors="replace")}

        entry = _sessions[conversation_id]

        # Resolve which key to verify against.
        if entry.remote_ik_sig_pub:
            sig_pub = entry.remote_ik_sig_pub
        elif sender_ik_sig_pub_hex:
            sig_pub = bytes.fromhex(sender_ik_sig_pub_hex)
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

    if method == "reset_session":
        conversation_id = params["conversation_id"]
        _sessions.pop(conversation_id, None)
        _pending_sessions.pop(conversation_id, None)
        try:
            store = _require_store()
            store.delete_session(conversation_id)
            store.delete_session(f"{_META_KEY_PREFIX}{conversation_id}")
        except Exception:
            pass
        return {"success": True}

    raise ValueError(f"Unknown method: {method!r}")


# ── TCP server ────────────────────────────────────────────────────────────────

def _process_line(line: bytes) -> bytes:
    req_id = None
    try:
        req    = json.loads(line.decode("utf-8"))
        req_id = req.get("id")
        result = _handle(req["method"], req.get("params") or {})
        resp   = {"id": req_id, **result}
    except InvalidTag:
        resp = {"id": req_id, "error": "Decryption failed — wrong password or tampered data"}
    except Exception as exc:
        resp = {"id": req_id, "error": str(exc) or repr(exc)}
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


def _check_peer_uid(conn: socket.socket) -> bool:
    """
    M1 fix: verify the connecting process is owned by the same UID as
    this service using SO_PEERCRED (Linux) or LOCAL_PEERCRED (macOS).

    Returns True if the peer UID matches os.getuid(), False otherwise.
    On platforms where neither option is available, logs a warning and
    returns True (fail-open) so the service remains functional — document
    this as a known limitation on unsupported platforms.
    """
    import struct
    own_uid = os.getuid()
    try:
        # Linux: SO_PEERCRED returns ucred { pid, uid, gid } (3 × uint32)
        SO_PEERCRED = 17
        cred = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12)
        _, peer_uid, _ = struct.unpack("III", cred)
        return peer_uid == own_uid
    except (OSError, AttributeError):
        pass
    try:
        # macOS: LOCAL_PEERCRED / LOCAL_PEEREPID
        import ctypes
        libc = ctypes.CDLL(None)
        LOCAL_PEERPID = 0x002  # macOS SOL_LOCAL option
        SOL_LOCAL = 0
        pid_buf = ctypes.c_int32(0)
        size    = ctypes.c_uint32(ctypes.sizeof(pid_buf))
        if libc.getsockopt(conn.fileno(), SOL_LOCAL, LOCAL_PEERPID,
                           ctypes.byref(pid_buf), ctypes.byref(size)) == 0:
            import pathlib
            uid_str = pathlib.Path(f"/proc/{pid_buf.value}/status").read_text()
            for line in uid_str.splitlines():
                if line.startswith("Uid:"):
                    peer_uid = int(line.split()[1])
                    return peer_uid == own_uid
    except Exception:
        pass
    # Platform not supported — fail-open with a warning.
    import logging as _log
    _log.getLogger(__name__).warning(
        "M1: SO_PEERCRED not available on this platform — "
        "peer UID check skipped. Document as known limitation."
    )
    return True


def main() -> None:
    # M1 fix: bind to a Unix domain socket in the keystore directory
    # (mode 0o600, owned by this user) instead of TCP 127.0.0.1:54231.
    # The directory itself is already created by StateStore with restrictive
    # permissions; the socket inherits those ownership constraints.
    sock_path = str(SOCKET_PATH)
    # Remove stale socket file from a previous run (bind fails otherwise).
    try:
        Path(sock_path).unlink()
    except FileNotFoundError:
        pass

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(sock_path)
        # Restrict socket to owner read/write only — no group or world access.
        Path(sock_path).chmod(0o600)
        srv.listen(5)  # M1 fix: was listen(1) — single-slot queue was a local DoS
        while True:
            conn, _ = srv.accept()
            # M1 fix: reject connections from processes not owned by this UID.
            if not _check_peer_uid(conn):
                conn.close()
                continue
            _serve_connection(conn)


if __name__ == "__main__":
    main()
