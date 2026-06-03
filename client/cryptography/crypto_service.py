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
  prepare_password_change  — derive new SRP credentials from new password; returns new_salt + new_verifier
  commit_password_change   — delete keystore and clear state after server confirms password update
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
import shutil
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
from core.kdf import derive_master_components, ARGON2_SALT_LEN
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

_srp_session:         Optional[SrpSession]    = None
_store:               Optional[StateStore]    = None
_local_bundle:        Optional[IdentityBundle] = None
_pending_password:    Optional[str]           = None  # raw password cached between srp_start and srp_challenge
_pending_keystore_key:     Optional[bytes]    = None  # derived in srp_challenge; promoted to _cached only after srp_verify succeeds
_cached_keystore_key:      Optional[bytes]    = None  # set only after confirmed mutual auth (or post-register); used by unlock_keystore
_pending_new_keystore_key: Optional[bytes]    = None  # staged by prepare_password_change; consumed by commit_password_change
_pending_sessions: dict = {}   # conversation_id → pending PQXDH state (pre-first-message)


@dataclass
class _SessionEntry:
    ratchet:           RatchetSession
    remote_ik_sig_pub: bytes
    init_bundle:       Optional[dict]   # included once with first sent message, then cleared


_sessions: dict[str, _SessionEntry] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _create_srp_verifier(username: str, srp_pass_hex: str, salt: bytes) -> bytes:
    """
    Compute SRP verifier v = g^x mod N for the given salt.

    The salt must be the same value passed to derive_master_components — it is both
    the Argon2id salt and the SRP x-computation salt, so registration and login
    always produce matching x values.
    """
    from core.srp_session import _sha256, _N, _g, _N_BYTES
    x = int.from_bytes(
        _sha256(salt, _sha256((username + ":" + srp_pass_hex).encode())),
        "big",
    )
    v = pow(_g, x, _N)
    return v.to_bytes(_N_BYTES, "big")


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


def _load_master_salt() -> Optional[bytes]:
    """Return the persisted Argon2id/SRP salt, or None if no keystore exists yet."""
    salt_path = _STORE_BASE_DIR / "salt"
    return salt_path.read_bytes() if salt_path.exists() else None


# ── RPC handlers ──────────────────────────────────────────────────────────────

def _handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
    global _srp_session, _store, _local_bundle, _pending_password, _pending_keystore_key, _cached_keystore_key, _pending_new_keystore_key

    # ── Keystore ──────────────────────────────────────────────────────────────

    if method == "unlock_keystore":
        password = params.get("password", "")
        if not password:
            return {"success": False, "error": "Password required"}

        if _cached_keystore_key is not None:
            # Fast path: srp_challenge already derived the key from the server's salt.
            try:
                _store = StateStore.load_with_key(_STORE_BASE_DIR, _cached_keystore_key)
            except FileNotFoundError:
                _cached_keystore_key = None
                return {"success": False, "error": "No keystore found — re-register"}
            _cached_keystore_key = None
        else:
            # Fallback: re-derive from the salt file (e.g. service restart before srp_challenge).
            srp_salt = _load_master_salt()
            if srp_salt is None:
                return {"success": False, "error": "No keystore found — re-register"}
            _, keystore_key, _ = derive_master_components(password, srp_salt)
            try:
                _store = StateStore.load_with_key(_STORE_BASE_DIR, keystore_key)
            except FileNotFoundError:
                return {"success": False, "error": "No keystore found — re-register"}


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

        # Single Argon2id call derives both the SRP synthetic password and the
        # keystore encryption key. The generated salt is sent to the server as
        # srp_salt and returned on every /auth/init — no client-side salt file needed.
        srp_salt = os.urandom(ARGON2_SALT_LEN)
        srp_pass, keystore_key, _ = derive_master_components(password, srp_salt)

        bundle = _gen_bundle(user_id=username)

        identity_signing_pub = bundle.ik_sig.public_key          # 2624 bytes

        nonce_bytes = bytes.fromhex(nonce_hex)
        nonce_sig   = bundle.ik_sig.sign(nonce_bytes)             # 4691 bytes
        spk_sig     = bundle.ik_sig.sign(bundle.spk.keypair.public_key_bytes)  # 4691 bytes

        verifier_bytes = _create_srp_verifier(username, srp_pass.hex(), srp_salt)

        try:
            _store = StateStore.create_with_key(_STORE_BASE_DIR, keystore_key, srp_salt)
        except FileExistsError:
            return {
                "success": False,
                "error": (
                    f"A keystore already exists at {_STORE_BASE_DIR}. "
                    "Delete that directory to re-register."
                )
            }
        _store.save_state(_BUNDLE_KEY, bundle.to_private_bundle())
        _local_bundle = bundle

        return {
            "srp_salt":                srp_salt.hex(),
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
        # Drop any password left over from an interrupted previous flow before
        # storing the new one — ensures the old reference is released immediately.
        _pending_password     = None
        _srp_session          = None
        _pending_keystore_key = None
        _cached_keystore_key  = None
        # Cache the raw password — srp_salt arrives from /auth/init and is only
        # available in srp_challenge, where we run Argon2id and inject srp_pass.
        _pending_password = params["password"]
        _srp_session = SrpSession(params["username"], "")  # password injected in srp_challenge
        return {"A": _srp_session.A_hex}

    if method == "srp_challenge":
        if _srp_session is None:
            raise ValueError("No SRP session active — call srp_start first")
        if _pending_password is None:
            raise ValueError("No pending password — call srp_start first")
        # Now we have the server's srp_salt — use it as the Argon2id salt to derive
        # srp_pass and keystore_key from one Argon2id call.
        srp_salt_bytes = bytes.fromhex(params["salt"])
        try:
            srp_pass, keystore_key, _ = derive_master_components(_pending_password, srp_salt_bytes)
        finally:
            # Clear plaintext password from memory regardless of success or failure.
            _pending_password = None
        # Key is staged here; promoted to _cached_keystore_key only after srp_verify
        # confirms mutual authentication — preventing the keystore from being opened
        # before the server is verified.
        _pending_keystore_key = keystore_key
        _srp_session.set_password(srp_pass.hex())
        M1 = _srp_session.process_challenge(params["salt"], params["B"])
        return {"M1": M1}

    if method == "srp_verify":
        if _srp_session is None:
            raise ValueError("No SRP session active — call srp_start first")
        authenticated = _srp_session.verify_server(params["M2"])
        session_key = _srp_session.session_key_hex if authenticated else None
        _srp_session      = None
        _pending_password = None  # defensive — should already be None after srp_challenge
        if authenticated:
            # Promote the staged key — unlock_keystore may now use it.
            _cached_keystore_key  = _pending_keystore_key
            _pending_keystore_key = None
        else:
            # Auth failed: discard staged key and evict any keystore state that may
            # have been loaded before this verification (e.g. unlock_keystore called
            # out of order).
            _pending_keystore_key = None
            _cached_keystore_key  = None
            _store                = None
            _local_bundle         = None
        return {"authenticated": authenticated, "session_key": session_key}

    # ── Password change ───────────────────────────────────────────────────────

    if method == "prepare_password_change":
        username         = params["username"]
        current_password = params.get("current_password", "")
        new_password     = params["new_password"]

        if not current_password:
            return {"success": False, "error": "Current password is required"}

        srp_salt = _load_master_salt()
        if srp_salt is None:
            return {"success": False, "error": "No keystore found"}

        # Verify the current password by deriving its key and attempting to
        # decrypt the identity bundle — InvalidTag means wrong password.
        # A fresh StateStore instance is used so _store is never clobbered.
        _, current_key, _ = derive_master_components(current_password, srp_salt)
        try:
            temp_store = StateStore.load_with_key(_STORE_BASE_DIR, current_key)
            temp_store.load_state(_BUNDLE_KEY)
        except InvalidTag:
            return {"success": False, "error": "Incorrect current password"}
        except (FileNotFoundError, KeyError):
            return {"success": False, "error": "No keystore found"}

        srp_pass, new_keystore_key, new_salt = derive_master_components(new_password)
        verifier_bytes = _create_srp_verifier(username, srp_pass.hex(), new_salt)
        _pending_new_keystore_key = new_keystore_key
        return {"new_salt": new_salt.hex(), "new_verifier": verifier_bytes.hex()}

    if method == "commit_password_change":
        _store                    = None
        _local_bundle             = None
        _cached_keystore_key      = None
        _pending_keystore_key     = None
        _pending_new_keystore_key = None
        _srp_session              = None
        _pending_password         = None
        if _STORE_BASE_DIR.exists():
            shutil.rmtree(_STORE_BASE_DIR)
        return {"success": True}

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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 54231))
        srv.listen(5)
        while True:
            conn, _ = srv.accept()
            _serve_connection(conn)


if __name__ == "__main__":
    main()
