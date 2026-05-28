"""
api/routes/session.py

Client-side authentication flow for the secure messaging API.

This is the CLIENT counterpart to the server's auth.js. It constructs and
sends the three-step authentication payloads defined in api/models.py,
then hands the session token back to the caller.

auth.js  — server: receives and verifies these requests
session.py — client: constructs and sends them

Three-step flow
---------------
1. register()   — upload identity bundle + credentials → device_id
2. challenge()  — request a 32-byte nonce for a device_id
3. verify()     — sign the nonce (Ed25519 + ML-DSA-87), send signatures → token

After verify() succeeds the caller holds a session token. Pass it as a
Bearer token in the Authorization header on all subsequent requests.

Session teardown
----------------
logout()      — invalidate the current session token (idle TTL: 30 min)
logout_all()  — invalidate all sessions for this device (e.g. on compromise)

The C++ TLS layer handles the actual HTTP transport. Each public function
in this module returns a dict ready to hand to the C++ layer, or raises
on any validation or authentication failure.

References:
    Signal PQXDH spec:  https://signal.org/docs/specifications/pqxdh/
    auth.js challenge-response design — see sessions.js in the server repo
"""

from __future__ import annotations

import base64
from typing import Optional

from api.models import (
    RegistrationBundle,
    DeviceBundle,
    ChallengeRequest,
    VerifyRequest,
)
from core.keys import IdentityBundle, SigningKeypair


# ── Exceptions ────────────────────────────────────────────────────────────────

class AuthenticationError(Exception):
    """
    Raised when the server rejects an authentication attempt.
    Wraps the server's error message. Do not expose to the UI verbatim —
    log it and show a generic failure message to the user.
    """


class RegistrationError(Exception):
    """
    Raised when registration fails.
    Common causes: username already taken, invalid key bundle.
    """


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> bytes:
    return base64.b64decode(s)


# ── Registration ──────────────────────────────────────────────────────────────

def build_registration_payload(
    username:        str,
    password:        str,
    identity_bundle: IdentityBundle,
    device_name:     Optional[str] = None,
) -> dict:
    """
    Build the POST /auth/register payload from a freshly generated
    IdentityBundle.

    Validates all fields via RegistrationBundle before returning, so
    the C++ layer receives a well-formed dict or this raises immediately.

    Parameters
    ----------
    username        : desired username (3–50 chars, [a-zA-Z0-9_])
    password        : plaintext password (min 12 chars) — never stored here
    identity_bundle : freshly generated IdentityBundle from core/keys.py
    device_name     : optional human-readable device label (max 100 chars)

    Returns
    -------
    dict : JSON-serialisable payload for C++ to POST to /auth/register

    Raises
    ------
    ValueError : if any field fails Pydantic validation
    """
    pub = identity_bundle.to_public_bundle()

    # Flatten OPK pairs into the format the server expects:
    # one_time_prekeys: list of base64 X25519 public keys
    # The server's auth.js stores these in one_time_prekeys table.
    # ML-KEM OPKs are uploaded separately via POST /keys/opks after registration.
    x25519_opk_pubs = [
        base64.b64encode(bytes.fromhex(opk["opk_pub"])).decode()
        for opk in pub["opks_x25519"]
    ]

    device = DeviceBundle(
        device_name              = device_name,
        idk_classical_pub        = base64.b64encode(
            bytes.fromhex(pub["ik_classical_pub"])
        ).decode(),
        idk_pq_pub               = base64.b64encode(
            bytes.fromhex(pub["ik_kem_pub"])
        ).decode(),
        identity_signing_pub     = base64.b64encode(
            bytes.fromhex(pub["ik_sig_pub"])
        ).decode(),
        identity_fingerprint     = _build_fingerprint(
            bytes.fromhex(pub["ik_classical_pub"]),
            bytes.fromhex(pub["ik_sig_pub"]),
        ),
        signed_prekey_pub        = base64.b64encode(
            bytes.fromhex(pub["spk_pub"])
        ).decode(),
        signed_prekey_signature  = base64.b64encode(
            bytes.fromhex(pub["spk_sig"])
        ).decode(),
        one_time_prekeys         = x25519_opk_pubs,
    )

    bundle = RegistrationBundle(
        username = username,
        password = password,
        device   = device,
    )
    return bundle.to_payload()


def _build_fingerprint(idk_classical_pub: bytes, ik_sig_pub: bytes) -> str:
    """
    Derive the identity fingerprint for TOFU pinning.
    SHA-256 of the classical identity key || signing public key.
    Matches the fingerprint construction in crypto_notes.md step 2.
    """
    import hashlib
    return hashlib.sha256(idk_classical_pub + ik_sig_pub).hexdigest()


def parse_registration_response(response: dict) -> str:
    """
    Extract device_id from a successful /auth/register response.

    Parameters
    ----------
    response : parsed JSON response body from the server

    Returns
    -------
    str : device_id UUID assigned by the server

    Raises
    ------
    RegistrationError : if the response is missing device_id or
                        indicates a server-side error
    """
    if "error" in response:
        raise RegistrationError(f"Registration failed: {response['error']}")
    if "deviceId" not in response:
        raise RegistrationError(
            f"Unexpected registration response — missing deviceId: {response}"
        )
    return str(response["deviceId"])


# ── Challenge ─────────────────────────────────────────────────────────────────

def build_challenge_payload(device_id: str) -> dict:
    """
    Build the POST /auth/challenge payload.

    Parameters
    ----------
    device_id : the device_id returned by registration

    Returns
    -------
    dict : JSON-serialisable payload for C++ to POST to /auth/challenge
    """
    return ChallengeRequest(device_id=device_id).to_payload()


def parse_challenge_response(response: dict) -> bytes:
    """
    Extract and decode the nonce from a /auth/challenge response.

    Parameters
    ----------
    response : parsed JSON response body from the server

    Returns
    -------
    bytes : 32-byte raw nonce to sign

    Raises
    ------
    AuthenticationError : if the response is missing the nonce or
                          indicates an error
    """
    if "error" in response:
        raise AuthenticationError(
            f"Challenge request failed: {response['error']}"
        )
    if "nonce" not in response:
        raise AuthenticationError(
            f"Unexpected challenge response — missing nonce: {response}"
        )
    try:
        nonce = bytes.fromhex(response["nonce"])
    except ValueError as exc:
        raise AuthenticationError(
            f"Challenge nonce is not valid hex: {response['nonce']!r}"
        ) from exc

    if len(nonce) != 32:
        raise AuthenticationError(
            f"Challenge nonce must be 32 bytes, got {len(nonce)}"
        )
    return nonce


# ── Verify ────────────────────────────────────────────────────────────────────

def build_verify_payload(
    device_id:      str,
    nonce:          bytes,
    signing_keypair: SigningKeypair,
    ed25519_priv,
) -> dict:
    """
    Sign the challenge nonce with both Ed25519 and ML-DSA-87 and build
    the POST /auth/verify payload.

    The server's auth.js verifies both signatures over the nonce via
    verifyDualSignature() — both must be valid for authentication to succeed.

    Parameters
    ----------
    device_id       : the device_id returned by registration
    nonce           : 32-byte raw nonce from parse_challenge_response()
    signing_keypair : ML-DSA-87 SigningKeypair (identity_bundle.ik_sig)
    ed25519_priv    : Ed25519PrivateKey (cryptography library) — the
                      classical leg of the dual-signature scheme

    Returns
    -------
    dict : JSON-serialisable payload for C++ to POST to /auth/verify

    Raises
    ------
    ValueError : if nonce is not 32 bytes
    """
    if len(nonce) != 32:
        raise ValueError(f"nonce must be 32 bytes, got {len(nonce)}")

    # Classical leg — Ed25519
    ed25519_sig: bytes = ed25519_priv.sign(nonce)

    # PQ leg — ML-DSA-87
    ml_dsa_sig: bytes = signing_keypair.sign(nonce)

    return VerifyRequest.from_signatures(
        device_id   = device_id,
        ed25519_sig = ed25519_sig,
        ml_dsa_sig  = ml_dsa_sig,
    ).to_payload()


def parse_verify_response(response: dict) -> str:
    """
    Extract the session token from a /auth/verify response.

    Parameters
    ----------
    response : parsed JSON response body from the server

    Returns
    -------
    str : session token (64-char hex string, 32 random bytes)
          Pass as 'Authorization: Bearer <token>' on all subsequent requests.

    Raises
    ------
    AuthenticationError : if the server rejected the signatures or the
                          response is malformed
    """
    if "error" in response:
        raise AuthenticationError(
            f"Authentication failed: {response['error']}"
        )
    if "token" not in response:
        raise AuthenticationError(
            f"Unexpected verify response — missing token: {response}"
        )
    return str(response["token"])


# ── Full login flow (convenience) ─────────────────────────────────────────────

def build_login_payloads(
    device_id:       str,
    nonce_response:  dict,
    signing_keypair: SigningKeypair,
    ed25519_priv,
) -> dict:
    """
    Convenience function: parse the challenge response and build the
    verify payload in one call.

    Typical login flow for the C++ layer:

        # Step 1 — send challenge request
        challenge_payload = build_challenge_payload(device_id)
        # ... C++ POSTs to /auth/challenge, gets response ...

        # Step 2 — sign nonce and build verify payload
        verify_payload = build_login_payloads(
            device_id       = device_id,
            nonce_response  = challenge_response,
            signing_keypair = identity_bundle.ik_sig,
            ed25519_priv    = ed25519_priv,
        )
        # ... C++ POSTs to /auth/verify, gets response ...

        # Step 3 — extract token
        token = parse_verify_response(verify_response)

    Parameters
    ----------
    device_id       : the device_id returned by registration
    nonce_response  : parsed JSON from /auth/challenge
    signing_keypair : ML-DSA-87 identity signing keypair
    ed25519_priv    : Ed25519PrivateKey for classical signature leg

    Returns
    -------
    dict : payload ready to POST to /auth/verify
    """
    nonce = parse_challenge_response(nonce_response)
    return build_verify_payload(
        device_id       = device_id,
        nonce           = nonce,
        signing_keypair = signing_keypair,
        ed25519_priv    = ed25519_priv,
    )


# ── Logout ────────────────────────────────────────────────────────────────────

def build_logout_payload() -> dict:
    """
    Build the POST /auth/logout payload.
    Invalidates the current session token (idle TTL: 30 min, absolute: 8 hr).
    The C++ layer must include the session token in the Authorization header.

    Returns
    -------
    dict : empty body — the server identifies the session from the token
    """
    return {}


def build_logout_all_payload() -> dict:
    """
    Build the POST /auth/logout-all payload.
    Invalidates ALL sessions for this device — use on suspected compromise
    or when switching devices.
    The C++ layer must include the session token in the Authorization header.

    Returns
    -------
    dict : empty body — the server identifies the device from the token
    """
    return {}
