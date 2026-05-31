"""
core/pqxdh.py

PQXDH (Post-Quantum Extended Diffie-Hellman) session initiation.

Implements the hybrid key agreement from the Signal PQXDH specification,
combining classical X3DH with ML-KEM-1024 for post-quantum forward secrecy.

HYBRID DESIGN RATIONALE (PQXDH spec §4)
  The scheme runs both a classical X25519 leg and a PQ ML-KEM-1024 leg in
  parallel. The final shared secret SK is derived from both outputs via HKDF.
  Security holds if EITHER primitive is unbroken:
    - Classical leg protects against a classical adversary if ML-KEM has an
      undiscovered weakness (it is a 2024 standard with limited cryptanalysis).
    - PQ leg protects against a quantum adversary recording traffic today for
      decryption once cryptographically relevant quantum computers exist
      ("harvest now, decrypt later").

CLASSICAL LEG (X3DH — RFC 7748, Signal X3DH spec)
  DH1 = X25519(IK_A_priv,   SPK_B_pub)          # Alice identity × Bob SPK
  DH2 = X25519(EK_A_priv,   IK_B_classical_pub)  # Alice ephemeral × Bob identity
  DH3 = X25519(EK_A_priv,   SPK_B_pub)           # Alice ephemeral × Bob SPK
  DH4 = X25519(EK_A_priv,   OPK_B_x25519_pub)    # Alice ephemeral × Bob X25519 OPK

PQ LEG (ML-KEM-1024 — FIPS 203)
  (CT_pq, SS_pq) = ML-KEM-1024.Encaps(OPK_B_kem_pub)
  -- if no ML-KEM OPK available, falls back to Bob's ML-KEM identity key
     (reduced PQ forward secrecy — documented as known limitation)

KEY DERIVATION (PQXDH spec §3.3)
  F   = 0xFF * 32  (padding constant — prevents cross-protocol attacks)
  IKM = F || DH1 || DH2 || DH3 || [DH4] || SS_pq
  SK  = HKDF-SHA256(IKM, salt=0x00*32, info=INFO_PQXDH_SK)

OPK PAIRING
  Each session initiation consumes one X25519 OPK (for DH4) and one ML-KEM
  OPK (for PQ encapsulation). Both are identified by the same opk_id so the
  responder can look up both secret keys from a single index.

  Remote bundles must provide both opks_x25519 and opks_kem as parallel
  lists with matching opk_ids at every index. The old combined "opks" format
  (opk_pub + opk_kem_pub in one list) is no longer supported.

TRUST MODEL
  TOFU with local pinning. First-contact MITM by a compromised server is a
  known limitation, documented in the design document.

References:
  Signal PQXDH spec:       https://signal.org/docs/specifications/pqxdh/
  Signal X3DH spec:        https://signal.org/docs/specifications/x3dh/
  FIPS 203 (ML-KEM-1024):  https://doi.org/10.6028/NIST.FIPS.203
  RFC 7748 (X25519):       https://www.rfc-editor.org/rfc/rfc7748
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Optional

import oqs

from core.keys import (
    KEM_ALG,
    IdentityBundle,
    MalformedSignedCiphertextError,
    X25519Keypair,
    verify_spk_signature,
)
from core.kdf import hkdf_derive, INFO_PQXDH_SK


# ── Constants ────────────────────────────────────────────────────────────────

# PQXDH spec §3.3 — padding constant prepended to IKM before HKDF.
# 32 bytes of 0xFF prevent cross-protocol confusion.
_PQXDH_F: bytes = b"\xff" * 32

# PQXDH spec §3.3 — HKDF salt is a 32-byte zero string.
PQXDH_HKDF_SALT: bytes = b"\x00" * 32

# HKDF output length — 32 bytes = 256-bit shared secret.
_SK_LEN: int = 32


# ── Exceptions ────────────────────────────────────────────────────────────────

class PQXDHError(Exception):
    """Base class for PQXDH errors."""

class SPKVerificationError(PQXDHError):
    """
    Raised when the SPK signature does not verify.
    Indicates a compromised server substituted a different prekey.
    Session initiation must be aborted.
    """

class NoPrekeyError(PQXDHError):
    """
    Raised when no one-time prekey is available and allow_no_opk=False.
    """

class MalformedBundleError(PQXDHError):
    """
    Raised when a remote bundle is missing required fields or has
    mismatched opks_x25519 / opks_kem lists.
    """


# ── Wire types ────────────────────────────────────────────────────────────────

@dataclass
class InitiationBundle:
    """
    The payload Alice sends to Bob to initiate a PQXDH session.

    Contains the information Bob needs to derive the same SK independently.
    SK itself is never included — it is derived by both parties separately.
    """
    ik_classical_pub:  bytes         # Alice's X25519 identity public key (32 bytes)
    ek_pub:            bytes         # Alice's X25519 ephemeral public key (32 bytes)
    ct_pq:             bytes         # ML-KEM-1024 ciphertext (1568 bytes)
    opk_id:            Optional[int] # which OPK pair Bob should use, or None
    used_identity_kem: bool          # True if PQ leg used IK not OPK (fallback)

    def to_dict(self) -> dict:
        return {
            "ik_classical_pub":  self.ik_classical_pub.hex(),
            "ek_pub":            self.ek_pub.hex(),
            "ct_pq":             self.ct_pq.hex(),
            "opk_id":            self.opk_id,
            "used_identity_kem": self.used_identity_kem,
        }

    @classmethod
    def from_dict(cls, d: dict) -> InitiationBundle:
        return cls(
            ik_classical_pub  = bytes.fromhex(d["ik_classical_pub"]),
            ek_pub            = bytes.fromhex(d["ek_pub"]),
            ct_pq             = bytes.fromhex(d["ct_pq"]),
            opk_id            = d.get("opk_id"),
            used_identity_kem = bool(d["used_identity_kem"]),
        )


@dataclass
class PQXDHResult:
    """Output of a successful PQXDH handshake."""
    SK:     bytes                       # 32-byte shared secret — seeds the ratchet
    bundle: Optional[InitiationBundle]  # None on responder side


# ── Bundle parsing ────────────────────────────────────────────────────────────

def _parse_remote_opks(
    remote_bundle: dict,
) -> tuple[list[dict], list[dict]]:
    """
    Extract and validate opks_x25519 and opks_kem from a remote public bundle.

    Both lists must be present, have the same length, and have matching
    opk_ids at every index. Raises MalformedBundleError on any violation.

    Returns (opks_x25519, opks_kem) as raw dicts for use in initiate().
    """
    if "opks_x25519" not in remote_bundle or "opks_kem" not in remote_bundle:
        raise MalformedBundleError(
            "Remote bundle is missing opks_x25519 or opks_kem. "
            "The old combined 'opks' format is no longer supported — "
            "ensure the remote device is running an up-to-date client."
        )

    opks_x25519: list[dict] = remote_bundle["opks_x25519"]
    opks_kem:    list[dict] = remote_bundle["opks_kem"]

    if len(opks_x25519) != len(opks_kem):
        raise MalformedBundleError(
            f"Remote bundle opks_x25519 and opks_kem have different lengths: "
            f"opks_x25519={len(opks_x25519)}, opks_kem={len(opks_kem)}. "
            f"Bundle may be corrupted or from a compromised server."
        )

    for i, (x_opk, k_opk) in enumerate(zip(opks_x25519, opks_kem)):
        if x_opk["opk_id"] != k_opk["opk_id"]:
            raise MalformedBundleError(
                f"Remote bundle OPK ID mismatch at index {i}: "
                f"opks_x25519[{i}].opk_id={x_opk['opk_id']}, "
                f"opks_kem[{i}].opk_id={k_opk['opk_id']}."
            )

    return opks_x25519, opks_kem


# ── Initiator (Alice) ─────────────────────────────────────────────────────────

def initiate(
    local_bundle:  IdentityBundle,
    remote_bundle: dict,
    allow_no_opk:  bool = False,
) -> PQXDHResult:
    """
    Perform PQXDH session initiation as Alice (the initiator).

    Parameters
    ----------
    local_bundle  : Alice's full IdentityBundle
    remote_bundle : Bob's public bundle dict (from to_public_bundle())
    allow_no_opk  : if True, fall back to ML-KEM identity key when no OPK
                    is available. If False, raise NoPrekeyError instead.

    Raises
    ------
    SPKVerificationError  : if Bob's SPK signature does not verify
    NoPrekeyError         : if no OPK is available and allow_no_opk=False
    MalformedBundleError  : if the remote bundle is missing or has mismatched
                            opks_x25519 / opks_kem lists
    """
    # ── Step 1: Parse Bob's public bundle ─────────────────────────────────────
    ik_b_classical  = bytes.fromhex(remote_bundle["ik_classical_pub"])
    ik_b_kem_pub    = bytes.fromhex(remote_bundle["ik_kem_pub"])
    ik_b_sig_pub    = bytes.fromhex(remote_bundle["ik_sig_pub"])
    spk_b_pub       = bytes.fromhex(remote_bundle["spk_pub"])
    spk_b_sig       = bytes.fromhex(remote_bundle["spk_sig"])
    spk_b_id        = remote_bundle["spk_id"]

    opks_x25519, opks_kem = _parse_remote_opks(remote_bundle)

    # ── Step 2: Verify SPK signature ──────────────────────────────────────────
    try:
        spk_valid = verify_spk_signature(spk_b_pub, spk_b_sig, ik_b_sig_pub)
    except MalformedSignedCiphertextError as exc:
        raise SPKVerificationError(
            f"SPK bundle is structurally invalid (spk_id={spk_b_id}): {exc}"
        ) from exc
    if not spk_valid:
        raise SPKVerificationError(
            f"SPK signature verification failed (spk_id={spk_b_id}). "
            f"Possible server substitution attack. Aborting."
        )

    # ── Step 3: Generate Alice's ephemeral X25519 keypair ─────────────────────
    ek_a = X25519Keypair.generate()

    # ── Step 4: Classical X3DH leg ────────────────────────────────────────────
    # DH1–DH3 are always computed. DH4 requires an X25519 OPK.
    dh1 = local_bundle.ik_classical.dh(spk_b_pub)
    dh2 = ek_a.dh(ik_b_classical)
    dh3 = ek_a.dh(spk_b_pub)

    opk_id_used = None
    dh4         = b""

    if opks_x25519:
        opk_x       = opks_x25519[0]
        opk_x_pub   = bytes.fromhex(opk_x["opk_pub"])
        opk_id_used = opk_x["opk_id"]
        dh4         = ek_a.dh(opk_x_pub)

    # ── Step 5: PQ leg (ML-KEM-1024) ──────────────────────────────────────────
    # Encapsulate to Bob's ML-KEM OPK (preferred) or identity key (fallback).
    # CT_pq is transmitted to Bob in the InitiationBundle.
    #
    # opks_x25519 and opks_kem are guaranteed to have the same length and
    # matching opk_ids by _parse_remote_opks — if opks_x25519 is non-empty
    # then opks_kem is also non-empty at the same index.
    used_identity_kem = False

    if opks_kem:
        # PQ OPK available — preferred path, best PQ forward secrecy
        opk_b_kem_pub = bytes.fromhex(opks_kem[0]["opk_pub"])
        ct_pq, ss_pq  = _kem_encapsulate(opk_b_kem_pub)
    elif allow_no_opk:
        # Fallback: encapsulate to Bob's ML-KEM identity key.
        # KNOWN LIMITATION: reduced PQ forward secrecy. Document in design doc.
        ct_pq, ss_pq  = _kem_encapsulate(ik_b_kem_pub)
        used_identity_kem = True
    else:
        raise NoPrekeyError(
            "No one-time prekey available and allow_no_opk=False. "
            "Retry later or set allow_no_opk=True (reduced PQ forward secrecy)."
        )

    # ── Step 6: Derive shared secret SK ──────────────────────────────────────
    # PQXDH spec §3.3:
    #   IKM = F || DH1 || DH2 || DH3 || [DH4] || SS_pq
    #   SK  = HKDF-SHA256(IKM, salt=b"", info=INFO_PQXDH_SK)
    #
    # F (0xFF * 32) prevents cross-protocol confusion.
    # SS_pq is appended last — the PQ leg wraps the classical material,
    # meaning a quantum adversary must break ML-KEM to recover SK even if
    # they can compute classical DH. (PQXDH spec §4, "Security Properties")
    ikm = bytearray(_PQXDH_F + dh1 + dh2 + dh3 + dh4 + ss_pq)
    SK  = hkdf_derive(
        ikm  = bytes(ikm),
        salt = PQXDH_HKDF_SALT,
        info = INFO_PQXDH_SK,
        length = _SK_LEN,
    )

    # Zeroise IKM — it holds all DH and KEM secrets combined.
    _zeroise(ikm)

    bundle = InitiationBundle(
        ik_classical_pub  = local_bundle.ik_classical.public_key_bytes,
        ek_pub            = ek_a.public_key_bytes,
        ct_pq             = ct_pq,
        opk_id            = opk_id_used,
        used_identity_kem = used_identity_kem,
    )

    return PQXDHResult(SK=SK, bundle=bundle)


# ── Responder (Bob) ───────────────────────────────────────────────────────────

def respond(
    local_bundle:      IdentityBundle,
    initiation:        InitiationBundle,
    local_x25519_opks: dict[int, bytes],  # {opk_id: X25519 secret key bytes}
    local_kem_opks:    dict[int, bytes],  # {opk_id: ML-KEM secret key bytes}
) -> PQXDHResult:
    """
    Perform PQXDH session response as Bob (the responder).

    Parameters
    ----------
    local_bundle      : Bob's full IdentityBundle
    initiation        : Alice's InitiationBundle
    local_x25519_opks : {opk_id: X25519 secret key bytes} — for DH4
    local_kem_opks    : {opk_id: ML-KEM secret key bytes} — for PQ decapsulation

    Returns
    -------
    PQXDHResult with SK. bundle is None — responder does not send one back.
    """
    ik_a_classical = initiation.ik_classical_pub
    ek_a_pub       = initiation.ek_pub
    ct_pq          = initiation.ct_pq
    opk_id         = initiation.opk_id

    # ── Classical X3DH leg ────────────────────────────────────────────────────
    dh1 = local_bundle.spk.keypair.dh(ik_a_classical)
    dh2 = local_bundle.ik_classical.dh(ek_a_pub)
    dh3 = local_bundle.spk.keypair.dh(ek_a_pub)

    dh4 = b""
    if opk_id is not None:
        if opk_id not in local_x25519_opks:
            raise PQXDHError(
                f"X25519 OPK id={opk_id} not found in local store. "
                f"OPK may have been consumed or bundle is replayed."
            )
        dh4 = _x25519_dh(local_x25519_opks[opk_id], ek_a_pub)

    # ── PQ leg — ML-KEM decapsulation ─────────────────────────────────────────
    if initiation.used_identity_kem:
        ss_pq = _kem_decapsulate(ct_pq, local_bundle.ik_kem.secret_key)
    else:
        if opk_id is None or opk_id not in local_kem_opks:
            raise PQXDHError(
                f"ML-KEM OPK id={opk_id} not found in local store. "
                f"Cannot decapsulate PQ ciphertext."
            )
        ss_pq = _kem_decapsulate(ct_pq, local_kem_opks[opk_id])

    # ── Derive shared secret SK ───────────────────────────────────────────────
    # Must produce the same SK as Alice — identical IKM construction.
    ikm = bytearray(_PQXDH_F + dh1 + dh2 + dh3 + dh4 + ss_pq)
    SK  = hkdf_derive(
        ikm    = bytes(ikm),
        salt   = PQXDH_HKDF_SALT,
        info   = INFO_PQXDH_SK,
        length = _SK_LEN,
    )

    _zeroise(ikm)

    return PQXDHResult(SK=SK, bundle=None)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to a ML-KEM-1024 public key. Returns (ciphertext, ss)."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ct, ss = kem.encap_secret(public_key)
    return ct, ss


def _kem_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Decapsulate a ML-KEM-1024 ciphertext. Returns shared secret."""
    with oqs.KeyEncapsulation(KEM_ALG, secret_key) as kem:
        return kem.decap_secret(ciphertext)


def _x25519_dh(secret_key_bytes: bytes, peer_public_bytes: bytes) -> bytes:
    """X25519 DH from raw secret key bytes (used by responder for OPKs)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey
    )
    priv = X25519PrivateKey.from_private_bytes(secret_key_bytes)
    pub  = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return priv.exchange(pub)


def _zeroise(*bufs) -> None:
    """
    Zeroisation of sensitive byte buffers.

    bytearray inputs are overwritten with zeros in place via ctypes — this
    reliably zeroes the underlying memory on CPython.

    bytes inputs are immutable; their memory cannot be zeroed from Python.
    The cryptography library zeroes its own key objects at the C layer.
    Callers should prefer bytearray for any buffer they construct (e.g. IKM).
    """
    for buf in bufs:
        if not buf:
            continue
        if isinstance(buf, bytearray):
            n = len(buf)
            ctypes.memset((ctypes.c_char * n).from_buffer(buf), 0, n)
