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
  DH1 = X25519(IK_A_priv,  SPK_B_pub)   # Alice identity × Bob signed prekey
  DH2 = X25519(EK_A_priv,  IK_B_pub)    # Alice ephemeral × Bob identity
  DH3 = X25519(EK_A_priv,  SPK_B_pub)   # Alice ephemeral × Bob signed prekey
  DH4 = X25519(EK_A_priv,  OPK_B_pub)   # Alice ephemeral × Bob OPK (if available)

PQ LEG (ML-KEM-1024 — FIPS 203)
  (CT_pq, SS_pq) = ML-KEM-1024.Encaps(OPK_B_pq_pub)
    -- if no PQ OPK available, falls back to ML-KEM encapsulation against
       Bob's ML-KEM identity key (reduced forward secrecy, documented below).

KEY DERIVATION (PQXDH spec §3.3)
  F       = 0xFF * 32  (PQXDH padding constant, prevents cross-protocol attacks)
  IKM     = F || DH1 || DH2 || DH3 || [DH4] || SS_pq
  SK      = HKDF-SHA256(IKM, salt=b"", info=INFO_PQXDH_SK)

TRUST MODEL
  TOFU (Trust On First Use) with local pinning. The first key bundle received
  from the server for a given user is trusted and pinned locally. Subsequent
  bundles are compared against the pinned key — a mismatch triggers a warning.
  A compromised server can MITM first-contact sessions (before pinning occurs)
  but cannot forge messages in established sessions where keys are pinned.
  This limitation is explicitly documented in the design document.

  SPK authenticity is verified via ML-DSA-87 signature before use. A server
  cannot substitute a different SPK without invalidating the signature.

OPK FALLBACK
  If no one-time prekey (OPK) is available from the server:
    allow_no_opk=True  → fall back to identity key encapsulation (weaker)
    allow_no_opk=False → raise NoPrekeyError (caller decides what to do)
  The fallback reduces PQ forward secrecy: the PQ shared secret is derived
  from the recipient's long-term identity key rather than a one-time key.
  This must be documented as a known limitation.

WIRE FORMAT (InitiationBundle sent from Alice to Bob)
  {
    ik_classical_pub : Alice's X25519 identity public key   (32 bytes hex)
    ek_pub           : Alice's X25519 ephemeral public key  (32 bytes hex)
    ct_pq            : ML-KEM-1024 ciphertext               (1568 bytes hex)
    opk_id           : OPK index used (int, or None if no OPK)
    used_identity_kem: bool — True if PQ leg used IK rather than OPK
  }

References:
  Signal PQXDH spec:       https://signal.org/docs/specifications/pqxdh/
  Signal X3DH spec:        https://signal.org/docs/specifications/x3dh/
  FIPS 203 (ML-KEM-1024):  https://doi.org/10.6028/NIST.FIPS.203
  RFC 7748 (X25519):       https://www.rfc-editor.org/rfc/rfc7748
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Optional

import oqs

from core.keys import (
    IdentityBundle,
    X25519Keypair,
    verify_spk_signature,
)
from core.kdf import hkdf_derive, INFO_PQXDH_SK
from core.constants import (
    KEM_ALG,
    SIG_ALG,
    PQXDH_F as _PQXDH_F,
    PQXDH_HKDF_SALT,
    PQXDH_SK_LEN as _SK_LEN,
)


# ── Exceptions ───────────────────────────────────────────────────────────────

class PQXDHError(Exception):
    """Base class for PQXDH errors."""

class SPKVerificationError(PQXDHError):
    """
    Raised when the SPK signature does not verify.
    Indicates a compromised server substituted a different prekey,
    or the bundle is corrupt. Session initiation must be aborted.
    """

class NoPrekeyError(PQXDHError):
    """
    Raised when no one-time prekey is available and allow_no_opk=False.
    Caller may retry later, prompt the user, or decide to allow fallback.
    """


# ── Wire types ────────────────────────────────────────────────────────────────

@dataclass
class InitiationBundle:
    """
    The payload Alice sends to Bob to initiate a PQXDH session.
    Bob needs this to derive the same SK and initialise his ratchet.

    Transmitted over the server (which relays but cannot read it —
    the shared secret SK is never included).
    """
    ik_classical_pub:  bytes   # Alice's X25519 identity public key (32 bytes)
    ek_pub:            bytes   # Alice's X25519 ephemeral public key (32 bytes)
    ct_pq:             bytes   # ML-KEM-1024 ciphertext (1568 bytes)
    opk_id:            Optional[int]   # which OPK Bob should use, or None
    used_identity_kem: bool    # True if PQ leg encapsulated to IK not OPK

    def to_dict(self) -> dict:
        """Serialise for transmission to the server / Bob."""
        return {
            "ik_classical_pub":  self.ik_classical_pub.hex(),
            "ek_pub":            self.ek_pub.hex(),
            "ct_pq":             self.ct_pq.hex(),
            "opk_id":            self.opk_id,
            "used_identity_kem": self.used_identity_kem,
        }

    @classmethod
    def from_dict(cls, d: dict) -> InitiationBundle:
        """Deserialise from a server-provided dict."""
        return cls(
            ik_classical_pub  = bytes.fromhex(d["ik_classical_pub"]),
            ek_pub            = bytes.fromhex(d["ek_pub"]),
            ct_pq             = bytes.fromhex(d["ct_pq"]),
            opk_id            = d.get("opk_id"),
            used_identity_kem = bool(d["used_identity_kem"]),
        )


@dataclass
class PQXDHResult:
    """
    Output of a successful PQXDH handshake — same structure for both
    initiator and responder.

    SK seeds the Double Ratchet. The bundle is sent to the other party
    (initiator sends it to responder; responder does not send one back).
    """
    SK:     bytes                    # 32-byte shared secret — seeds the ratchet
    bundle: Optional[InitiationBundle]  # None on responder side


# ── Initiator (Alice) ─────────────────────────────────────────────────────────

def initiate(
    local_bundle:  IdentityBundle,
    remote_bundle: dict,
    allow_no_opk:  bool = False,
) -> PQXDHResult:
    """
    Perform PQXDH session initiation as Alice (the initiator).

    Fetches Bob's public key bundle (as a dict from the server), verifies
    the SPK signature, runs the hybrid X3DH + ML-KEM key agreement, and
    derives the shared secret SK.

    Parameters
    ----------
    local_bundle  : Alice's full IdentityBundle (keys.py)
    remote_bundle : Bob's public bundle dict (from to_public_bundle())
    allow_no_opk  : if True, fall back to ML-KEM identity key when no OPK
                    is available. If False, raise NoPrekeyError instead.
                    Document the chosen policy in your design document.

    Returns
    -------
    PQXDHResult with SK (seeds the ratchet) and bundle (send to Bob)

    Raises
    ------
    SPKVerificationError : if Bob's SPK signature does not verify
    NoPrekeyError        : if no OPK is available and allow_no_opk=False
    """
    # ── Step 1: Parse Bob's public bundle ────────────────────────────────────
    ik_b_classical = bytes.fromhex(remote_bundle["ik_classical_pub"])
    ik_b_kem_pub   = bytes.fromhex(remote_bundle["ik_kem_pub"])
    ik_b_sig_pub   = bytes.fromhex(remote_bundle["ik_sig_pub"])
    spk_b_pub      = bytes.fromhex(remote_bundle["spk_pub"])
    spk_b_sig      = bytes.fromhex(remote_bundle["spk_sig"])
    spk_b_id       = remote_bundle["spk_id"]
    opks           = remote_bundle.get("opks", [])

    # ── Step 2: Verify SPK signature ─────────────────────────────────────────
    # Critical: a compromised server cannot substitute a different SPK without
    # invalidating this signature. Abort if verification fails.
    if not verify_spk_signature(spk_b_pub, spk_b_sig, ik_b_sig_pub):
        raise SPKVerificationError(
            f"SPK signature verification failed for remote bundle "
            f"(spk_id={spk_b_id}). Possible server substitution attack. "
            f"Aborting session initiation."
        )

    # ── Step 3: Generate Alice's ephemeral X25519 keypair ────────────────────
    # Fresh per session — never reuse ephemeral keys.
    ek_a = X25519Keypair.generate()

    # ── Step 4: Classical X3DH leg ───────────────────────────────────────────
    # Signal X3DH spec §3.3 — four DH computations:
    #   DH1: Alice identity    × Bob signed prekey
    #   DH2: Alice ephemeral   × Bob identity
    #   DH3: Alice ephemeral   × Bob signed prekey
    #   DH4: Alice ephemeral   × Bob one-time prekey (if available)
    dh1 = local_bundle.ik_classical.dh(spk_b_pub)
    dh2 = ek_a.dh(ik_b_classical)
    dh3 = ek_a.dh(spk_b_pub)

    opk_id_used    = None
    dh4            = b""

    if opks:
        # Use the first available OPK — server should remove it after delivery
        opk            = opks[0]
        opk_b_pub      = bytes.fromhex(opk["opk_pub"])
        opk_id_used    = opk["opk_id"]
        dh4            = ek_a.dh(opk_b_pub)

    # ── Step 5: PQ leg (ML-KEM-1024) ─────────────────────────────────────────
    # Encapsulate to Bob's OPK (preferred) or identity key (fallback).
    # The ciphertext CT_pq is sent to Bob in the InitiationBundle.
    # Bob decapsulates to recover SS_pq.
    used_identity_kem = False

    if opks:
        # PQ OPK available — preferred path, best PQ forward secrecy
        opk_b_kem_pub = bytes.fromhex(opks[0]["opk_kem_pub"])
        ct_pq, ss_pq  = _kem_encapsulate(opk_b_kem_pub)
    elif allow_no_opk:
        # Fallback: encapsulate to Bob's ML-KEM identity key.
        # KNOWN LIMITATION: SS_pq is derived from a long-term key rather
        # than a one-time key. PQ forward secrecy is reduced — if Bob's
        # ML-KEM identity key is later compromised, this session's PQ leg
        # is retroactively broken. Document explicitly in design document.
        ct_pq, ss_pq  = _kem_encapsulate(ik_b_kem_pub)
        used_identity_kem = True
    else:
        raise NoPrekeyError(
            "No one-time prekey available for this recipient and "
            "allow_no_opk=False. Retry later or set allow_no_opk=True "
            "to fall back to identity key encapsulation (reduced PQ "
            "forward secrecy — document this in your design document)."
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
        salt = PQXDH_HKDF_SALT,   # PQXDH spec §3.3: salt is a zero string
        info = INFO_PQXDH_SK,
        length = _SK_LEN,
    )

    # Zeroise IKM — it holds all DH and KEM secrets combined.
    # ikm is a bytearray so _zeroise can overwrite it in place.
    # dh1..ss_pq are immutable bytes from the crypto library; we drop references.
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
    local_bundle:     IdentityBundle,
    initiation:       InitiationBundle,
    local_opks:       dict[int, bytes],  # {opk_id: opk_secret_key}
    local_kem_opk_sks: dict[int, bytes], # {opk_id: kem_opk_secret_key}
) -> PQXDHResult:
    """
    Perform PQXDH session response as Bob (the responder).

    Receives Alice's InitiationBundle, decapsulates the ML-KEM ciphertext,
    recomputes the same four X3DH DH outputs, and derives SK.

    Parameters
    ----------
    local_bundle      : Bob's full IdentityBundle
    initiation        : Alice's InitiationBundle (from InitiationBundle.from_dict())
    local_opks        : mapping of OPK id → X25519 secret key bytes
                        (Bob's one-time prekey secret keys, stored locally)
    local_kem_opk_sks : mapping of OPK id → ML-KEM secret key bytes
                        (Bob's ML-KEM OPK secret keys, stored locally)

    Returns
    -------
    PQXDHResult with SK (seeds the ratchet). bundle is None — responder
    does not send a bundle back.

    Raises
    ------
    PQXDHError : if the OPK referenced in the bundle is not found locally,
                 or if decapsulation fails.
    """
    # ── Step 1: Parse Alice's initiation bundle ───────────────────────────────
    ik_a_classical = initiation.ik_classical_pub
    ek_a_pub       = initiation.ek_pub
    ct_pq          = initiation.ct_pq
    opk_id         = initiation.opk_id

    # ── Step 2: Classical X3DH leg ───────────────────────────────────────────
    # Bob recomputes the same four DH outputs as Alice, using his private keys.
    # DH is symmetric: DH(a_priv, b_pub) == DH(b_priv, a_pub) for X25519.
    dh1 = local_bundle.spk.keypair.dh(ik_a_classical)
    dh2 = local_bundle.ik_classical.dh(ek_a_pub)
    dh3 = local_bundle.spk.keypair.dh(ek_a_pub)

    dh4 = b""
    if opk_id is not None:
        if opk_id not in local_opks:
            raise PQXDHError(
                f"OPK id={opk_id} referenced in initiation bundle not found "
                f"in local OPK store. The OPK may have been consumed already "
                f"or the bundle is replayed."
            )
        opk_b_sec = local_opks[opk_id]
        dh4 = _x25519_dh(opk_b_sec, ek_a_pub)

    # ── Step 3: PQ leg — ML-KEM decapsulation ────────────────────────────────
    if initiation.used_identity_kem:
        # Alice encapsulated to Bob's ML-KEM identity key (fallback path)
        ss_pq = _kem_decapsulate(ct_pq, local_bundle.ik_kem.secret_key)
    else:
        # Alice encapsulated to a ML-KEM OPK
        if opk_id is None or opk_id not in local_kem_opk_sks:
            raise PQXDHError(
                f"ML-KEM OPK secret key for id={opk_id} not found locally. "
                f"Cannot decapsulate PQ ciphertext."
            )
        kem_opk_sk = local_kem_opk_sks[opk_id]
        ss_pq      = _kem_decapsulate(ct_pq, kem_opk_sk)

    # ── Step 4: Derive shared secret SK ──────────────────────────────────────
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
    """
    Encapsulate to a ML-KEM-1024 public key.
    Returns (ciphertext, shared_secret).
    """
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ct, ss = kem.encap_secret(public_key)
    return ct, ss


def _kem_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Decapsulate a ML-KEM-1024 ciphertext using the secret key.
    Returns the shared secret.
    """
    with oqs.KeyEncapsulation(KEM_ALG, secret_key) as kem:
        return kem.decap_secret(ciphertext)


def _x25519_dh(secret_key_bytes: bytes, peer_public_bytes: bytes) -> bytes:
    """
    Perform X25519 DH from raw secret key bytes.
    Used by the responder when loading OPK secret keys from local storage.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
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
