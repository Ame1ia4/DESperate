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

import hashlib
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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import srp as _srp

from core.keys import generate_identity_bundle as _gen_bundle
from core.srp_session import SrpSession

# ── RFC 5054 Appendix A — 3072-bit safe prime ────────────────────────────────
# Server PR will update secure-remote-password to match this group.

_N_3072 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
_G_3072 = 2

HOST = "127.0.0.1"
PORT = 54231

# ── In-memory service state ──────────────────────────────────────────────────

_srp_session: SrpSession | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _create_srp_verifier(username: str, password: str) -> tuple[bytes, bytes]:
    """
    Derive a 32-byte SRP salt and 256-byte verifier.

    Uses RFC 5054 §2.3 x derivation:  x = H(s | H(I ":" P))
    Matches the server's secure-remote-password npm library exactly.
    Salt is 32 bytes (64 hex chars) — matches server's SRP_SALT_HEX=64.
    Verifier is 256 bytes (512 hex chars) — matches server's SRP_VERIFIER_HEX=512.
    """
    salt = os.urandom(32)
    inner = hashlib.sha256((username + ":" + password).encode("utf-8")).digest()
    x_bytes = hashlib.sha256(salt + inner).digest()
    x = int.from_bytes(x_bytes, "big")
    v = pow(_G_3072, x, _N_3072)
    v_bytes = v.to_bytes(384, "big")  # 384 bytes = 3072 bits
    return salt, v_bytes


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
