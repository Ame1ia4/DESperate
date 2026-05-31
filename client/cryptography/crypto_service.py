"""
crypto_service.py — Local cryptography microservice for the DESperate client.

Listens on TCP 127.0.0.1:54231 for newline-delimited JSON-RPC requests.

Protocol:
  Request:  {"id": "...", "method": "...", "params": {...}}\n
  Success:  {"id": "...", ...result_fields...}\n
  Failure:  {"id": "...", "error": "message"}\n

Compile to a standalone binary with PyInstaller:
  pyinstaller --onedir --name crypto_service crypto_service.py
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

# Allow imports from the package root when run as __main__ or frozen.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

import srp as _srp

from core.keys import generate_identity_bundle as _gen_bundle, IdentityBundle
from core.srp_session import SrpSession, _SRP_3072_KWARGS
from core.password import derive_master_components
from core.state_store import encrypt_blob, decrypt_blob, _atomic_write

HOST = "127.0.0.1"
PORT = 54231

# ── On-disk paths (all under ~/.desperate/) ──────────────────────────────────

_APP_DIR          = Path.home() / ".desperate"
_MASTER_SALT_PATH = _APP_DIR / "master_salt"   # Argon2id salt — written once at registration
_IDENTITY_PATH    = _APP_DIR / "identity.enc"  # Encrypted private key bundle
_USER_ID_PATH     = _APP_DIR / "user_id"       # Plaintext username — used to reconstruct AD

# ── In-memory service state ──────────────────────────────────────────────────

_srp_session:         SrpSession | None      = None
_cached_keystore_key: bytes | None           = None  # set by srp_start, consumed by unlock_keystore
_identity_bundle:     IdentityBundle | None  = None  # loaded by unlock_keystore
_ed25519_priv:        Ed25519PrivateKey | None = None  # loaded by unlock_keystore, used for signing


# ── Helpers ──────────────────────────────────────────────────────────────────

def _create_srp_verifier(username: str, password: str) -> tuple[bytes, bytes]:
    """
    Derive an SRP salt and verifier via pysrp (NG_3072, SHA-256).

    Using pysrp guarantees the x derivation matches what SrpSession uses
    internally on the login path — a hand-rolled derivation risks silent
    auth failure for every registered user if any byte-level detail diverges.

    Salt is ~32 bytes; verifier is ~384 bytes (3072-bit group).
    """
    salt, verifier = _srp.create_salted_verification_key(
        username, password, **_SRP_3072_KWARGS
    )
    return salt, verifier


def _identity_ad(user_id: str) -> bytes:
    """Associated data for the identity bundle — binds the ciphertext to this user."""
    return f"desperate-v1:identity:{user_id}".encode()


def _write_master_salt(salt: bytes) -> None:
    _MASTER_SALT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _MASTER_SALT_PATH.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        f.write(salt)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(_MASTER_SALT_PATH)


def _load_master_salt() -> bytes:
    if not _MASTER_SALT_PATH.exists():
        raise FileNotFoundError(
            "Master salt not found — register before logging in."
        )
    return _MASTER_SALT_PATH.read_bytes()


def _dual_sign(ed25519_priv: Ed25519PrivateKey, mldsa_secret: bytes, message: bytes) -> bytes:
    """
    Produce a dual signature: Ed25519 (64 B) || ML-DSA-87 (4627 B) = 4691 bytes.
    Matches server's DUAL_SIG_BYTES = ED25519_SIG_BYTES + MLDSA_SIG_BYTES.
    """
    import oqs
    from core.constants import SIG_ALG

    ed_sig = ed25519_priv.sign(message)
    with oqs.Signature(SIG_ALG, mldsa_secret) as signer:
        ml_sig = signer.sign(message)
    return ed_sig + ml_sig


# ── RPC handlers ─────────────────────────────────────────────────────────────

def _handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
    global _srp_session, _cached_keystore_key

    # ── SRP authentication ────────────────────────────────────────────────────

    if method == "srp_start":
        # Discard any stale session from a previous incomplete flow.
        _srp_session = None
        _cached_keystore_key = None
        master_salt = _load_master_salt()
        srp_pass, keystore_key, _ = derive_master_components(
            params["password"], master_salt
        )
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
        _srp_session = None
        if not authenticated:
            _cached_keystore_key = None
        return {"authenticated": authenticated}

    # ── Key bundle generation (registration) ──────────────────────────────────

    if method == "generate_identity_bundle":
        username  = params["username"]
        password  = params["password"]
        nonce_hex = params["nonce"]

        bundle = _gen_bundle(user_id=username)

        # Ed25519 keypair for the classical signing leg of the hybrid signing key.
        # The server's identity_signing_pub = Ed25519_pub (32 B) || ML-DSA-87_pub (2592 B).
        ed25519_priv = Ed25519PrivateKey.generate()
        ed25519_pub  = ed25519_priv.public_key().public_bytes_raw()

        identity_signing_pub = ed25519_pub + bundle.ik_sig.public_key

        nonce_bytes = bytes.fromhex(nonce_hex)
        nonce_sig   = _dual_sign(ed25519_priv, bundle.ik_sig.secret_key, nonce_bytes)
        spk_sig     = _dual_sign(ed25519_priv, bundle.ik_sig.secret_key,
                                 bundle.spk.keypair.public_key_bytes)

        srp_pass, keystore_key, master_salt = derive_master_components(password)
        _write_master_salt(master_salt)
        salt_bytes, verifier_bytes = _create_srp_verifier(username, srp_pass.hex())

        # Encrypt and persist private key bundle at rest.
        private_data = bundle.to_private_bundle()
        private_data["ed25519_sec"] = ed25519_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        ).hex()
        plaintext = json.dumps(private_data, separators=(",", ":")).encode()
        blob = encrypt_blob(keystore_key, plaintext, _identity_ad(username))
        _atomic_write(_IDENTITY_PATH, blob)
        _atomic_write(_USER_ID_PATH, username.encode())

        return {
            "srp_salt":               salt_bytes.hex(),
            "srp_verifier":           verifier_bytes.hex(),
            "idk_classical_pub":      bundle.ik_classical.public_key_bytes.hex(),
            "idk_pq_pub":             bundle.ik_kem.public_key.hex(),
            "identity_signing_pub":   identity_signing_pub.hex(),
            "signed_prekey_pub":      bundle.spk.keypair.public_key_bytes.hex(),
            "signed_prekey_signature": spk_sig.hex(),
            "nonce":                  nonce_hex,
            "nonce_signature":        nonce_sig.hex(),
        }

    # ── Keystore ──────────────────────────────────────────────────────────────

    if method == "unlock_keystore":
        global _identity_bundle, _ed25519_priv
        password = params.get("password", "")
        if not password:
            return {"success": False, "error": "Password required"}
        # Use the keystore key cached during srp_start if available;
        # otherwise re-derive (e.g. unlock called standalone without SRP).
        keystore_key = _cached_keystore_key
        _cached_keystore_key = None
        if keystore_key is None:
            master_salt = _load_master_salt()
            _, keystore_key, _ = derive_master_components(password, master_salt)
        try:
            user_id   = _USER_ID_PATH.read_bytes().decode()
            blob      = _IDENTITY_PATH.read_bytes()
            plaintext = decrypt_blob(keystore_key, blob, _identity_ad(user_id))
        except (FileNotFoundError, InvalidTag):
            return {"success": False, "error": "Keystore unlock failed"}
        private_data     = json.loads(plaintext.decode())
        ed25519_sec_hex  = private_data.pop("ed25519_sec")
        _identity_bundle = IdentityBundle.from_private_bundle(private_data)
        _ed25519_priv    = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed25519_sec_hex))
        return {"success": True}

    # ── Message encryption/decryption (Double Ratchet) ────────────────────────

    if method == "encrypt_message":
        raise NotImplementedError("encrypt_message: Double Ratchet not yet wired")

    if method == "decrypt_message":
        raise NotImplementedError("decrypt_message: Double Ratchet not yet wired")

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
