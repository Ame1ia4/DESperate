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
import socket
import sys
from pathlib import Path
from typing import Any

# Allow imports from the package root when run as __main__ or frozen.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import srp as _srp

from core.keys import generate_identity_bundle as _gen_bundle
from core.srp_session import SrpSession, _SRP_3072_KWARGS

HOST = "127.0.0.1"
PORT = 54231

# ── In-memory service state ──────────────────────────────────────────────────

_srp_session: SrpSession | None = None


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
    global _srp_session

    # ── SRP authentication ────────────────────────────────────────────────────

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
        _srp_session = None
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

        salt_bytes, verifier_bytes = _create_srp_verifier(username, password)

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
        # Keystore unlock verifies the password can decrypt local state.
        # For now, accept any non-empty password — full implementation
        # requires a persisted encrypted keystore (state_store.py).
        password = params.get("password", "")
        if not password:
            return {"success": False, "error": "Password required"}
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
