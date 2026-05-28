"""
api/routes/keys.py

Public key distribution and OPK replenishment for the secure messaging API.

These routes serve and maintain the public key material stored in the
`devices` and `one_time_prekeys` tables. All routes require an authenticated
session except GET /keys/{device_id} (public key lookup is intentionally
unauthenticated — anyone in a conversation needs to fetch a recipient's bundle
before initiating a session).

Four endpoints
--------------
GET  /keys/{device_id}     — fetch a device's full public bundle for PQXDH
POST /keys/opks            — upload a fresh batch of X25519 + ML-KEM OPKs
PUT  /keys/spk             — rotate the signed prekey (every 30 days)
GET  /keys/opk-status      — check remaining OPK count for this device

CLIENT vs SERVER
----------------
This file is the CLIENT side — it builds request payloads and parses
responses. The server-side handler (Node.js) stores and serves the keys.

OPK REPLENISHMENT FLOW
-----------------------
The server tracks OPK counts per device. When a device's unused OPK count
falls below opk_low_watermark (25, from system_config), the server signals
this in any response via {"opk_low": true}. The client should then call
build_opk_replenishment_payload() and POST to /keys/opks.

Use replenish_one_time_prekeys() from core/keys.py to generate the new
batch — never generate OPKs independently of that function, as it enforces
the X25519/ML-KEM pairing invariant.

KEY ROTATION
------------
Signed prekeys must be rotated every 30 days (system_config:
signed_prekey_rotation_days). The client is responsible for tracking
rotation age locally and calling build_spk_rotation_payload() when due.
The server does not enforce rotation — it only tracks signed_prekey_created_at.

References:
    Signal X3DH spec §3:   https://signal.org/docs/specifications/x3dh/
    Signal PQXDH spec §3:  https://signal.org/docs/specifications/pqxdh/
    DB schema:             one_time_prekeys, devices tables
"""

from __future__ import annotations

import base64
from typing import Optional

from core.keys import (
    IdentityBundle,
    SigningKeypair,
    X25519OneTimePrekey,
    KEMOneTimePrekey,
    SignedPrekey,
    generate_signed_prekey,
    generate_opk_pairs,
    replenish_one_time_prekeys,
    verify_spk_signature,
)
from core.constants import OPK_COUNT


# ── Exceptions ────────────────────────────────────────────────────────────────

class KeyFetchError(Exception):
    """Raised when fetching a remote key bundle fails or the bundle is invalid."""


class KeyUploadError(Exception):
    """Raised when uploading OPKs or rotating the SPK fails."""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _hex(data: bytes) -> str:
    return data.hex()


# ── GET /keys/{device_id} ─────────────────────────────────────────────────────

def parse_key_bundle_response(response: dict) -> dict:
    """
    Parse and validate a remote device's public key bundle from
    GET /keys/{device_id}.

    Performs the following checks before returning:
      - All required fields are present
      - SPK signature verifies against the identity signing key
      - opks_x25519 and opks_kem are present with matching opk_ids

    The caller must additionally pin the identity_fingerprint on first
    contact (TOFU) and reject any future bundle where it changes.

    Parameters
    ----------
    response : parsed JSON response body from the server

    Returns
    -------
    dict with validated fields:
        ik_classical_pub     : bytes (32)   — X25519 identity key
        ik_kem_pub           : bytes (1568) — ML-KEM-1024 identity key
        ik_sig_pub           : bytes (2592) — ML-DSA-87 signing key
        identity_fingerprint : str          — hex SHA-256 for TOFU pinning
        spk_id               : int
        spk_pub              : bytes (32)   — X25519 signed prekey
        spk_sig              : bytes        — ML-DSA-87 signature over spk_pub
        opks_x25519          : list[dict]   — [{opk_id, opk_pub: bytes}]
        opks_kem             : list[dict]   — [{opk_id, opk_pub: bytes}]

    Raises
    ------
    KeyFetchError : if any required field is missing, SPK verification
                    fails, or OPK lists are mismatched
    """
    if "error" in response:
        raise KeyFetchError(f"Key bundle fetch failed: {response['error']}")

    required = {
        "ik_classical_pub", "ik_kem_pub", "ik_sig_pub",
        "identity_fingerprint",
        "spk_id", "spk_pub", "spk_sig",
        "opks_x25519", "opks_kem",
    }
    missing = required - response.keys()
    if missing:
        raise KeyFetchError(
            f"Key bundle missing required fields: {sorted(missing)}"
        )

    try:
        ik_classical_pub = bytes.fromhex(response["ik_classical_pub"])
        ik_kem_pub       = bytes.fromhex(response["ik_kem_pub"])
        ik_sig_pub       = bytes.fromhex(response["ik_sig_pub"])
        spk_pub          = bytes.fromhex(response["spk_pub"])
        spk_sig          = bytes.fromhex(response["spk_sig"])
    except (ValueError, TypeError) as exc:
        raise KeyFetchError(f"Key bundle contains invalid hex: {exc}") from exc

    # ── SPK signature verification ────────────────────────────────────────────
    # Verify before using any other field — a compromised server cannot forge
    # a valid ML-DSA-87 signature without the device's secret signing key.
    if not verify_spk_signature(
        spk_pub    = spk_pub,
        signature  = spk_sig,
        ik_sig_pub = ik_sig_pub,
    ):
        raise KeyFetchError(
            "SPK signature verification failed for device bundle. "
            "Possible server key substitution attack — aborting session initiation."
        )

    # ── OPK list validation ───────────────────────────────────────────────────
    opks_x25519_raw: list[dict] = response["opks_x25519"]
    opks_kem_raw:    list[dict] = response["opks_kem"]

    if len(opks_x25519_raw) != len(opks_kem_raw):
        raise KeyFetchError(
            f"OPK list length mismatch in remote bundle: "
            f"opks_x25519={len(opks_x25519_raw)}, opks_kem={len(opks_kem_raw)}"
        )

    opks_x25519 = []
    opks_kem    = []

    for i, (x_raw, k_raw) in enumerate(zip(opks_x25519_raw, opks_kem_raw)):
        if x_raw["opk_id"] != k_raw["opk_id"]:
            raise KeyFetchError(
                f"OPK ID mismatch at index {i}: "
                f"opks_x25519[{i}].opk_id={x_raw['opk_id']}, "
                f"opks_kem[{i}].opk_id={k_raw['opk_id']}"
            )
        try:
            opks_x25519.append({
                "opk_id":  x_raw["opk_id"],
                "opk_pub": bytes.fromhex(x_raw["opk_pub"]),
            })
            opks_kem.append({
                "opk_id":  k_raw["opk_id"],
                "opk_pub": bytes.fromhex(k_raw["opk_pub"]),
            })
        except (ValueError, TypeError) as exc:
            raise KeyFetchError(
                f"Invalid hex in OPK at index {i}: {exc}"
            ) from exc

    return {
        "ik_classical_pub":   ik_classical_pub,
        "ik_kem_pub":         ik_kem_pub,
        "ik_sig_pub":         ik_sig_pub,
        "identity_fingerprint": response["identity_fingerprint"],
        "spk_id":             response["spk_id"],
        "spk_pub":            spk_pub,
        "spk_sig":            spk_sig,
        "opks_x25519":        opks_x25519,
        "opks_kem":           opks_kem,
    }


# ── POST /keys/opks ───────────────────────────────────────────────────────────

def build_opk_replenishment_payload(
    existing_x25519_opks: list[X25519OneTimePrekey],
    existing_kem_opks:    list[KEMOneTimePrekey],
    target_count:         int = OPK_COUNT,
) -> tuple[dict, list[X25519OneTimePrekey], list[KEMOneTimePrekey]]:
    """
    Generate a fresh OPK batch and build the POST /keys/opks payload.

    Uses replenish_one_time_prekeys() to ensure the X25519 and ML-KEM
    lists are always generated together with matching opk_ids.

    After the server responds with 200, the caller must persist the new
    private keys to state_store.py before discarding this function's
    return value. If the upload fails, the generated keys must be discarded
    — do not retry with the same keys.

    Parameters
    ----------
    existing_x25519_opks : current X25519 OPKs in local state (unused only)
    existing_kem_opks    : current ML-KEM OPKs in local state (unused only)
    target_count         : desired total OPK count (default from constants)

    Returns
    -------
    (payload, new_x25519_opks, new_kem_opks)
        payload          : dict for C++ to POST to /keys/opks
        new_x25519_opks  : generated X25519 OPKs — persist private keys
        new_kem_opks     : generated ML-KEM OPKs — persist private keys

    Raises
    ------
    AssertionError : if existing lists have mismatched lengths or IDs
                     (state corruption — must be resolved before replenishing)
    """
    new_x25519, new_kem = replenish_one_time_prekeys(
        existing_x25519 = existing_x25519_opks,
        existing_kem    = existing_kem_opks,
        target_count    = target_count,
    )

    if not new_x25519:
        # Already at target — nothing to upload
        return {}, [], []

    payload = {
        "opks_x25519": [
            {"opk_id": opk.opk_id, "opk_pub": _hex(opk.public_key)}
            for opk in new_x25519
        ],
        "opks_kem": [
            {"opk_id": opk.opk_id, "opk_pub": _hex(opk.public_key)}
            for opk in new_kem
        ],
    }

    return payload, new_x25519, new_kem


def parse_opk_upload_response(response: dict) -> int:
    """
    Parse the server's response to POST /keys/opks.

    Parameters
    ----------
    response : parsed JSON response body

    Returns
    -------
    int : number of OPKs now stored on the server

    Raises
    ------
    KeyUploadError : if the server rejected the upload
    """
    if "error" in response:
        raise KeyUploadError(f"OPK upload failed: {response['error']}")
    return int(response.get("opk_count", 0))


# ── PUT /keys/spk ─────────────────────────────────────────────────────────────

def build_spk_rotation_payload(
    identity_bundle: IdentityBundle,
    new_spk_id:      int,
) -> tuple[dict, SignedPrekey]:
    """
    Generate a new signed prekey and build the PUT /keys/spk payload.

    The SPK is signed by the device's ML-DSA-87 identity key so the server
    and other clients can verify it was legitimately issued by this device.

    Rotation policy: every 30 days (system_config: signed_prekey_rotation_days).
    The caller is responsible for tracking the last rotation date locally.

    After the server responds with 200, the caller must:
      1. Persist the new SPK private key to state_store.py
      2. Update the local IdentityBundle with the new SPK
      3. Retain the old SPK private key until all in-flight sessions using
         it have completed (grace period — see Signal X3DH spec §4)

    Parameters
    ----------
    identity_bundle : the device's current IdentityBundle (for the signing key)
    new_spk_id      : monotonically increasing SPK ID (increment from current)

    Returns
    -------
    (payload, new_spk)
        payload : dict for C++ to PUT to /keys/spk
        new_spk : new SignedPrekey — persist private key before discarding

    Raises
    ------
    ValueError : if new_spk_id is not greater than the current SPK ID
    """
    current_spk_id = identity_bundle.spk.spk_id
    if new_spk_id <= current_spk_id:
        raise ValueError(
            f"new_spk_id ({new_spk_id}) must be greater than "
            f"current spk_id ({current_spk_id})"
        )

    new_spk = generate_signed_prekey(
        signing_keypair = identity_bundle.ik_sig,
        spk_id          = new_spk_id,
    )

    payload = {
        "spk_id":  new_spk.spk_id,
        "spk_pub": _hex(new_spk.keypair.public_key_bytes),
        "spk_sig": _hex(new_spk.signature),
    }

    return payload, new_spk


def parse_spk_rotation_response(response: dict) -> None:
    """
    Validate the server's response to PUT /keys/spk.

    Raises
    ------
    KeyUploadError : if the server rejected the rotation
    """
    if "error" in response:
        raise KeyUploadError(f"SPK rotation failed: {response['error']}")


# ── GET /keys/opk-status ──────────────────────────────────────────────────────

def parse_opk_status_response(response: dict) -> dict:
    """
    Parse the server's response to GET /keys/opk-status.

    Returns
    -------
    dict:
        opk_count    : int  — number of unused OPKs remaining on server
        opk_low      : bool — True if below opk_low_watermark (25)
        low_watermark: int  — the configured watermark threshold

    Raises
    ------
    KeyFetchError : if the response is malformed
    """
    if "error" in response:
        raise KeyFetchError(f"OPK status fetch failed: {response['error']}")

    try:
        return {
            "opk_count":     int(response["opk_count"]),
            "opk_low":       bool(response.get("opk_low", False)),
            "low_watermark": int(response.get("low_watermark", 25)),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise KeyFetchError(
            f"Malformed OPK status response: {exc}"
        ) from exc


def should_replenish(opk_status: dict) -> bool:
    """
    Return True if the device should upload a fresh OPK batch.

    Replenishment is needed when the server's unused OPK count is below
    the low watermark (opk_low_watermark = 25 from system_config).

    Parameters
    ----------
    opk_status : dict returned by parse_opk_status_response()
    """
    return opk_status["opk_low"]
