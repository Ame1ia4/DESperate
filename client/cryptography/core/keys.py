"""
core/keys.py

PQXDH key bundle generation.

Generates and manages cryptographic identity material for each user:
  - ML-KEM-1024  identity keypair  (key encapsulation, NIST FIPS 203 level 5)
  - ML-DSA-87    signing keypair   (signatures,        NIST FIPS 204 level 5)
  - X25519       identity keypair  (classical DH leg of hybrid PQXDH)
  - X25519       signed prekey     (SPK, rotated periodically)
  - ML-KEM-1024  one-time prekeys  (OPKs, consumed per session initiation)

Key sizes at ML-KEM-1024 / ML-DSA-87 (NIST level 5):
  ML-KEM-1024  public key : 1568 bytes
  ML-KEM-1024  secret key : 3168 bytes
  ML-KEM-1024  ciphertext : 1568 bytes
  ML-DSA-87    public key : 2592 bytes
  ML-DSA-87    secret key : 4896 bytes
  ML-DSA-87    signature  : 4627 bytes
  X25519       public key :   32 bytes
  X25519       secret key :   32 bytes

References:
  PQXDH specification: https://signal.org/docs/specifications/pqxdh/
  FIPS 203 (ML-KEM):   https://doi.org/10.6028/NIST.FIPS.203
  FIPS 204 (ML-DSA):   https://doi.org/10.6028/NIST.FIPS.204
  RFC 7748 (X25519):   https://www.rfc-editor.org/rfc/rfc7748
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

import oqs  # liboqs-python — pip install liboqs-python

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from .constants import (
    KEM_ALG,
    SIG_ALG,
    OPK_COUNT,
    KEM_PUBLIC_KEY_LEN,
    KEM_CIPHERTEXT_LEN,
    DSA_PUBLIC_KEY_LEN,
    DSA_SIGNATURE_LEN,
)


# ── Key size assertions (fail fast if liboqs version is unexpected) ──────────

def _assert_key_sizes() -> None:
    """
    Verify expected key/ciphertext sizes against the running liboqs version.
    Raises AssertionError on mismatch — surfaces version drift immediately
    rather than silently producing wrong-sized keys.
    """
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        pub = kem.generate_keypair()
        ct, _ = kem.encap_secret(pub)
        assert len(pub) == KEM_PUBLIC_KEY_LEN, f"ML-KEM-1024 public key: expected {KEM_PUBLIC_KEY_LEN}, got {len(pub)}"
        assert len(ct)  == KEM_CIPHERTEXT_LEN, f"ML-KEM-1024 ciphertext: expected {KEM_CIPHERTEXT_LEN}, got {len(ct)}"

    with oqs.Signature(SIG_ALG) as sig:
        pub = sig.generate_keypair()
        s   = sig.sign(b"probe")
        assert len(pub) == DSA_PUBLIC_KEY_LEN, f"ML-DSA-87 public key: expected {DSA_PUBLIC_KEY_LEN}, got {len(pub)}"
        assert len(s)   == DSA_SIGNATURE_LEN,  f"ML-DSA-87 signature:  expected {DSA_SIGNATURE_LEN}, got {len(s)}"


# ── Keypair dataclasses ──────────────────────────────────────────────────────

@dataclass
class KEMKeypair:
    """
    ML-KEM-1024 keypair.
    public_key  — safe to upload to server / share with contacts
    secret_key  — never leaves the device; encrypt at rest (see storage/)
    """
    public_key: bytes
    secret_key: bytes

    def public_bytes(self) -> bytes:
        return self.public_key

    def __repr__(self) -> str:
        return f"KEMKeypair(public={self.public_key.hex()[:16]}…)"


@dataclass
class SigningKeypair:
    """
    ML-DSA-87 keypair.
    public_key  — safe to upload to server / share with contacts
    secret_key  — never leaves the device; encrypt at rest (see storage/)
    """
    public_key: bytes
    secret_key: bytes

    def sign(self, message: bytes) -> bytes:
        """Sign message. Returns raw ML-DSA-87 signature (4627 bytes)."""
        with oqs.Signature(SIG_ALG, self.secret_key) as signer:
            return signer.sign(message)

    def __repr__(self) -> str:
        return f"SigningKeypair(public={self.public_key.hex()[:16]}…)"


@dataclass
class X25519Keypair:
    """
    Classical X25519 keypair (hybrid leg of PQXDH).
    Provides classical security while ML-KEM provides PQ security.
    Both must be broken for the scheme to fail — see PQXDH spec §4.
    """
    _private: X25519PrivateKey

    @classmethod
    def generate(cls) -> X25519Keypair:
        return cls(X25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def private_key_bytes(self) -> bytes:
        return self._private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def dh(self, peer_public_bytes: bytes) -> bytes:
        """Perform X25519 DH with a peer's raw public key bytes."""
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self._private.exchange(peer_pub)

    def __repr__(self) -> str:
        return f"X25519Keypair(public={self.public_key_bytes.hex()[:16]}…)"


@dataclass
class OneTimePrekey:
    """
    A single PQXDH one-time prekey (OPK) — contains both legs:
      x25519_keypair : X25519 classical leg (DH4 in X3DH)
      public_key     : ML-KEM-1024 public key (PQ encapsulation target)
      secret_key     : ML-KEM-1024 secret key (PQ decapsulation)

    Each OPK is consumed by exactly one PQXDH session initiation.
    The server tracks which OPKs remain; clients must replenish when low.

    opk_id — server-assigned identifier, returned to initiator so
             the recipient knows which OPK was used for DH4 / decapsulation.
    """
    opk_id:         int
    x25519_keypair: X25519Keypair  # classical DH4 leg
    public_key:     bytes          # ML-KEM-1024 public key  (1568 bytes)
    secret_key:     bytes          # ML-KEM-1024 secret key  (3168 bytes)

    def __repr__(self) -> str:
        return f"OneTimePrekey(id={self.opk_id}, public={self.public_key.hex()[:16]}…)"


@dataclass
class SignedPrekey:
    """
    X25519 signed prekey (SPK).
    The SPK is signed by the user's ML-DSA-87 identity key so that
    the initiating party can verify it genuinely belongs to the recipient,
    even if served by a compromised server.

    Rotation policy: rotate weekly (see PQXDH spec §3.3).
    For this deployment: manual rotation via /keys/rotate_spk endpoint.

    spk_id      — monotonically increasing, lets server and clients track
                  which SPK is current
    signature   — ML-DSA-87 signature over the SPK public key bytes,
                  produced by the user's ML-DSA-87 identity key
    """
    spk_id:     int
    keypair:    X25519Keypair
    signature:  bytes           # sig over keypair.public_key_bytes

    def __repr__(self) -> str:
        return (
            f"SignedPrekey(id={self.spk_id}, "
            f"public={self.keypair.public_key_bytes.hex()[:16]}…)"
        )


# ── Full identity bundle ─────────────────────────────────────────────────────

@dataclass
class IdentityBundle:
    """
    Complete PQXDH identity bundle for one user.

    Private material (ik_kem, ik_sig, ik_classical, spk, opks secret keys)
    must be encrypted at rest — see storage/state_store.py.

    Public material (to_public_bundle()) is uploaded to the server on
    registration and re-uploaded whenever the SPK or OPKs are rotated.
    """
    user_id:      str
    ik_kem:       KEMKeypair        # ML-KEM-1024 identity keypair
    ik_sig:       SigningKeypair    # ML-DSA-87   identity keypair
    ik_classical: X25519Keypair     # X25519      identity keypair
    spk:          SignedPrekey      # X25519      signed prekey
    opks:         list[OneTimePrekey] = field(default_factory=list)

    def to_public_bundle(self) -> dict:
        """
        Serialise the public half of this bundle for upload to the server.
        The server stores this and serves it to initiating parties.
        No private key material is included.
        """
        return {
            "user_id":           self.user_id,
            "ik_kem_pub":        self.ik_kem.public_key.hex(),
            "ik_sig_pub":        self.ik_sig.public_key.hex(),
            "ik_classical_pub":  self.ik_classical.public_key_bytes.hex(),
            "spk_id":            self.spk.spk_id,
            "spk_pub":           self.spk.keypair.public_key_bytes.hex(),
            "spk_sig":           self.spk.signature.hex(),
            "opks": [
                {
                    "opk_id":      opk.opk_id,
                    "opk_pub":     opk.x25519_keypair.public_key_bytes.hex(),
                    "opk_kem_pub": opk.public_key.hex(),
                }
                for opk in self.opks
            ],
        }

    def to_private_bundle(self) -> dict:
        """
        Serialise the full bundle including private keys for encrypted
        local storage. This output must be encrypted before writing to
        disk — never store this in plaintext.
        """
        return {
            "user_id":               self.user_id,
            "ik_kem_pub":            self.ik_kem.public_key.hex(),
            "ik_kem_sec":            self.ik_kem.secret_key.hex(),
            "ik_sig_pub":            self.ik_sig.public_key.hex(),
            "ik_sig_sec":            self.ik_sig.secret_key.hex(),
            "ik_classical_pub":      self.ik_classical.public_key_bytes.hex(),
            "ik_classical_sec":      self.ik_classical.private_key_bytes.hex(),
            "spk_id":                self.spk.spk_id,
            "spk_pub":               self.spk.keypair.public_key_bytes.hex(),
            "spk_sec":               self.spk.keypair.private_key_bytes.hex(),
            "spk_sig":               self.spk.signature.hex(),
            "opks": [
                {
                    "opk_id":      opk.opk_id,
                    "opk_pub":     opk.x25519_keypair.public_key_bytes.hex(),
                    "opk_sec":     opk.x25519_keypair.private_key_bytes.hex(),
                    "opk_kem_pub": opk.public_key.hex(),
                    "opk_kem_sec": opk.secret_key.hex(),
                }
                for opk in self.opks
            ],
        }

    def __repr__(self) -> str:
        return (
            f"IdentityBundle(user_id={self.user_id!r}, "
            f"opks={len(self.opks)})"
        )


# ── Generation functions ─────────────────────────────────────────────────────

def generate_kem_keypair() -> KEMKeypair:
    """Generate a fresh ML-KEM-1024 keypair."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return KEMKeypair(public_key=public_key, secret_key=secret_key)


def generate_signing_keypair() -> SigningKeypair:
    """Generate a fresh ML-DSA-87 keypair."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
    return SigningKeypair(public_key=public_key, secret_key=secret_key)


def generate_signed_prekey(
    signing_keypair: SigningKeypair,
    spk_id: int = 1,
) -> SignedPrekey:
    """
    Generate a fresh X25519 signed prekey.
    The SPK public key is signed with the user's ML-DSA-87 identity key,
    allowing initiators to verify the SPK genuinely belongs to this user
    even if served by a compromised server.
    """
    spk_keypair = X25519Keypair.generate()
    signature   = signing_keypair.sign(spk_keypair.public_key_bytes)
    return SignedPrekey(
        spk_id    = spk_id,
        keypair   = spk_keypair,
        signature = signature,
    )


def generate_one_time_prekeys(
    count: int = OPK_COUNT,
    start_id: int = 1,
) -> list[OneTimePrekey]:
    """
    Generate a batch of PQXDH one-time prekeys (both classical and PQ legs).
    Each OPK is consumed by exactly one PQXDH session initiation.
    The server must not reuse OPKs — if no OPKs remain, the initiator
    falls back to the SPK only (reduced forward secrecy, document this).
    """
    opks = []
    for i in range(count):
        x25519_keypair = X25519Keypair.generate()
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        opks.append(OneTimePrekey(
            opk_id         = start_id + i,
            x25519_keypair = x25519_keypair,
            public_key     = public_key,
            secret_key     = secret_key,
        ))
    return opks


def generate_identity_bundle(
    user_id:   str,
    opk_count: int = OPK_COUNT,
) -> IdentityBundle:
    """
    Generate a complete PQXDH identity bundle for a new user.
    Call this once on registration — the result is:
      1. Private bundle → encrypted and stored locally (storage/state_store.py)
      2. Public bundle  → uploaded to the server (/keys/bundle endpoint)

    Parameters
    ----------
    user_id   : the user's identifier (e.g. username or UUID)
    opk_count : number of one-time prekeys to generate (default 20)
    """
    ik_kem       = generate_kem_keypair()
    ik_sig       = generate_signing_keypair()
    ik_classical = X25519Keypair.generate()
    spk          = generate_signed_prekey(ik_sig, spk_id=1)
    opks         = generate_one_time_prekeys(count=opk_count, start_id=1)

    return IdentityBundle(
        user_id      = user_id,
        ik_kem       = ik_kem,
        ik_sig       = ik_sig,
        ik_classical = ik_classical,
        spk          = spk,
        opks         = opks,
    )


def verify_spk_signature(
    spk_pub:    bytes,
    signature:  bytes,
    ik_sig_pub: bytes,
) -> bool:
    """
    Verify that an SPK was signed by the expected ML-DSA-87 identity key.
    Call this when receiving a key bundle from the server before using the SPK.
    Returns True if valid, False if the signature does not verify.

    A False result means either:
      - The server tampered with the SPK (compromised server attack), or
      - The bundle is corrupt.
    In either case, abort the session initiation.
    """
    with oqs.Signature(SIG_ALG) as verifier:
        return verifier.verify(spk_pub, signature, ik_sig_pub)


def replenish_one_time_prekeys(
    existing_opks: list[OneTimePrekey],
    target_count:  int = OPK_COUNT,
) -> list[OneTimePrekey]:
    """
    Generate additional OPKs to bring the total back up to target_count.
    Call this when the server reports fewer than target_count OPKs remaining.
    New OPK IDs continue from the highest existing ID to avoid collisions.
    """
    if not existing_opks:
        return generate_one_time_prekeys(count=target_count, start_id=1)

    highest_id = max(opk.opk_id for opk in existing_opks)
    shortfall  = target_count - len(existing_opks)

    if shortfall <= 0:
        return []

    return generate_one_time_prekeys(count=shortfall, start_id=highest_id + 1)
