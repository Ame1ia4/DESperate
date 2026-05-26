"""
core/keys.py

PQXDH key bundle generation.

Generates and manages cryptographic identity material for each user:
  - ML-KEM-1024  identity keypair     (key encapsulation, NIST FIPS 203 level 5)
  - ML-DSA-87    signing keypair      (signatures,        NIST FIPS 204 level 5)
  - X25519       identity keypair     (classical DH leg of hybrid PQXDH)
  - X25519       signed prekey        (SPK, rotated periodically)
  - X25519       one-time prekeys     (classical DH4 leg per session)
  - ML-KEM-1024  one-time prekeys     (PQ encapsulation leg per session)

Each PQXDH session initiation consumes one X25519 OPK (for DH4) and one
ML-KEM OPK (for PQ encapsulation). Both are identified by the same opk_id
so the responder can look up both secret keys from a single index.

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

from dataclasses import dataclass, field

import oqs

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
from core.constants import (
    KEM_ALG,
    SIG_ALG,
    OPK_COUNT,
    KEM_PUBLIC_KEY_LEN,
    KEM_CIPHERTEXT_LEN,
    DSA_PUBLIC_KEY_LEN,
    DSA_SIGNATURE_LEN,
)


# ── Key size assertions ───────────────────────────────────────────────────────

def _assert_key_sizes() -> None:
    """
    Verify expected key/ciphertext sizes against the running liboqs version.
    Raises AssertionError on mismatch — surfaces version drift immediately
    rather than silently producing wrong-sized keys.
    """
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        pub = kem.generate_keypair()
        ct, _ = kem.encap_secret(pub)
        assert len(pub) == KEM_PUBLIC_KEY_LEN, \
            f"ML-KEM-1024 public key: expected {KEM_PUBLIC_KEY_LEN}, got {len(pub)}"
        assert len(ct) == KEM_CIPHERTEXT_LEN, \
            f"ML-KEM-1024 ciphertext: expected {KEM_CIPHERTEXT_LEN}, got {len(ct)}"

    with oqs.Signature(SIG_ALG) as sig:
        pub = sig.generate_keypair()
        s   = sig.sign(b"probe")
        assert len(pub) == DSA_PUBLIC_KEY_LEN, \
            f"ML-DSA-87 public key: expected {DSA_PUBLIC_KEY_LEN}, got {len(pub)}"
        assert len(s) == DSA_SIGNATURE_LEN, \
            f"ML-DSA-87 signature: expected {DSA_SIGNATURE_LEN}, got {len(s)}"


# ── Keypair dataclasses ───────────────────────────────────────────────────────

@dataclass
class KEMKeypair:
    """ML-KEM-1024 keypair. secret_key never leaves the device."""
    public_key: bytes
    secret_key: bytes

    def public_bytes(self) -> bytes:
        return self.public_key

    def __repr__(self) -> str:
        return f"KEMKeypair(public={self.public_key.hex()[:16]}…)"


@dataclass
class SigningKeypair:
    """ML-DSA-87 keypair. secret_key never leaves the device."""
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
    Both X25519 and ML-KEM must be broken for the scheme to fail.
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
        """Perform X25519 DH with a peer's raw 32-byte public key."""
        if len(peer_public_bytes) != 32:
            raise ValueError(
                f"X25519 public key must be 32 bytes, got {len(peer_public_bytes)}. "
                f"Ensure you are passing an X25519 key, not an ML-KEM key."
            )
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self._private.exchange(peer_pub)

    def __repr__(self) -> str:
        return f"X25519Keypair(public={self.public_key_bytes.hex()[:16]}…)"


@dataclass
class X25519OneTimePrekey:
    """
    A single X25519 one-time prekey (OPK).

    Used for the classical DH4 leg of PQXDH. Paired with a ML-KEM OPK of
    the same opk_id for the PQ encapsulation leg. Both are consumed together
    in a single session initiation.

    opk_id must match the corresponding ML-KEMOneTimePrekey opk_id so the
    responder can look up both secret keys from a single index.
    """
    opk_id:     int
    public_key: bytes   # 32 bytes
    secret_key: bytes   # 32 bytes

    def __repr__(self) -> str:
        return f"X25519OneTimePrekey(id={self.opk_id}, public={self.public_key.hex()[:16]}…)"


@dataclass
class KEMOneTimePrekey:
    """
    A single ML-KEM-1024 one-time prekey (OPK).

    Used for the PQ encapsulation leg of PQXDH. Paired with an X25519 OPK
    of the same opk_id for the classical DH4 leg.

    opk_id must match the corresponding X25519OneTimePrekey opk_id.
    """
    opk_id:     int
    public_key: bytes   # 1568 bytes (ML-KEM-1024)
    secret_key: bytes   # 3168 bytes (ML-KEM-1024)

    def __repr__(self) -> str:
        return f"KEMOneTimePrekey(id={self.opk_id}, public={self.public_key.hex()[:16]}…)"


@dataclass
class SignedPrekey:
    """
    X25519 signed prekey (SPK).
    Signed by the user's ML-DSA-87 identity key.
    Rotation policy: rotate weekly (PQXDH spec §3.3).
    """
    spk_id:    int
    keypair:   X25519Keypair
    signature: bytes   # ML-DSA-87 signature over keypair.public_key_bytes

    def __repr__(self) -> str:
        return (
            f"SignedPrekey(id={self.spk_id}, "
            f"public={self.keypair.public_key_bytes.hex()[:16]}…)"
        )


# ── Full identity bundle ──────────────────────────────────────────────────────

@dataclass
class IdentityBundle:
    """
    Complete PQXDH identity bundle for one user.

    Contains two separate OPK lists:
      x25519_opks — X25519 OPKs for the classical DH4 leg
      kem_opks    — ML-KEM OPKs for the PQ encapsulation leg

    Both lists are indexed by opk_id. A session initiation consumes the
    X25519 OPK and ML-KEM OPK with the same opk_id.

    Private material must be encrypted at rest (state_store.py).
    Public material is uploaded to the server via to_public_bundle().
    """
    user_id:      str
    ik_kem:       KEMKeypair
    ik_sig:       SigningKeypair
    ik_classical: X25519Keypair
    spk:          SignedPrekey
    x25519_opks:  list[X25519OneTimePrekey] = field(default_factory=list)
    kem_opks:     list[KEMOneTimePrekey]    = field(default_factory=list)

    def to_public_bundle(self) -> dict:
        """
        Serialise the public half of this bundle for upload to the server.
        No private key material is included.

        The server serves this to initiating parties. The two OPK lists are
        kept separate so the initiator clearly knows which keys are X25519
        (for DH4) and which are ML-KEM (for PQ encapsulation).
        """
        return {
            "user_id":          self.user_id,
            "ik_kem_pub":       self.ik_kem.public_key.hex(),
            "ik_sig_pub":       self.ik_sig.public_key.hex(),
            "ik_classical_pub": self.ik_classical.public_key_bytes.hex(),
            "spk_id":           self.spk.spk_id,
            "spk_pub":          self.spk.keypair.public_key_bytes.hex(),
            "spk_sig":          self.spk.signature.hex(),
            # X25519 OPKs — 32-byte public keys for classical DH4
            "opks_x25519": [
                {"opk_id": opk.opk_id, "opk_pub": opk.public_key.hex()}
                for opk in self.x25519_opks
            ],
            # ML-KEM OPKs — 1568-byte public keys for PQ encapsulation
            "opks_kem": [
                {"opk_id": opk.opk_id, "opk_pub": opk.public_key.hex()}
                for opk in self.kem_opks
            ],
        }

    def to_private_bundle(self) -> dict:
        """
        Serialise the full bundle including private keys for encrypted
        local storage. Never store this output in plaintext.
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
            "opks_x25519": [
                {
                    "opk_id":  opk.opk_id,
                    "opk_pub": opk.public_key.hex(),
                    "opk_sec": opk.secret_key.hex(),
                }
                for opk in self.x25519_opks
            ],
            "opks_kem": [
                {
                    "opk_id":  opk.opk_id,
                    "opk_pub": opk.public_key.hex(),
                    "opk_sec": opk.secret_key.hex(),
                }
                for opk in self.kem_opks
            ],
        }

    def __repr__(self) -> str:
        return (
            f"IdentityBundle(user_id={self.user_id!r}, "
            f"x25519_opks={len(self.x25519_opks)}, "
            f"kem_opks={len(self.kem_opks)})"
        )


# ── Generation functions ──────────────────────────────────────────────────────

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
    The SPK public key is signed with the user's ML-DSA-87 identity key.
    """
    spk_keypair = X25519Keypair.generate()
    signature   = signing_keypair.sign(spk_keypair.public_key_bytes)
    return SignedPrekey(
        spk_id    = spk_id,
        keypair   = spk_keypair,
        signature = signature,
    )


def generate_one_time_prekeys(
    count:    int = OPK_COUNT,
    start_id: int = 1,
) -> tuple[list[X25519OneTimePrekey], list[KEMOneTimePrekey]]:
    """
    Generate paired X25519 and ML-KEM one-time prekeys.

    Returns two lists of equal length. Prekeys at the same index share the
    same opk_id — a session initiation consumes both with the same id.

    Returns
    -------
    (x25519_opks, kem_opks) : paired lists of OPKs
    """
    x25519_opks = []
    kem_opks    = []

    for i in range(count):
        opk_id = start_id + i

        # X25519 OPK — for classical DH4 leg
        kp = X25519Keypair.generate()
        x25519_opks.append(X25519OneTimePrekey(
            opk_id     = opk_id,
            public_key = kp.public_key_bytes,
            secret_key = kp.private_key_bytes,
        ))

        # ML-KEM OPK — for PQ encapsulation leg
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            pub = kem.generate_keypair()
            sec = kem.export_secret_key()
        kem_opks.append(KEMOneTimePrekey(
            opk_id     = opk_id,
            public_key = pub,
            secret_key = sec,
        ))

    return x25519_opks, kem_opks


def generate_identity_bundle(
    user_id:   str,
    opk_count: int = OPK_COUNT,
) -> IdentityBundle:
    """
    Generate a complete PQXDH identity bundle for a new user.

    Parameters
    ----------
    user_id   : the user's identifier (e.g. username or UUID)
    opk_count : number of OPK pairs to generate (default from constants)
    """
    ik_kem          = generate_kem_keypair()
    ik_sig          = generate_signing_keypair()
    ik_classical    = X25519Keypair.generate()
    spk             = generate_signed_prekey(ik_sig, spk_id=1)
    x25519_opks, kem_opks = generate_one_time_prekeys(
        count=opk_count, start_id=1
    )

    return IdentityBundle(
        user_id      = user_id,
        ik_kem       = ik_kem,
        ik_sig       = ik_sig,
        ik_classical = ik_classical,
        spk          = spk,
        x25519_opks  = x25519_opks,
        kem_opks     = kem_opks,
    )


def verify_spk_signature(
    spk_pub:    bytes,
    signature:  bytes,
    ik_sig_pub: bytes,
) -> bool:
    """
    Verify that an SPK was signed by the expected ML-DSA-87 identity key.
    Returns True if valid. Returns False if tampered — abort session initiation.
    """
    with oqs.Signature(SIG_ALG) as verifier:
        return verifier.verify(spk_pub, signature, ik_sig_pub)


def replenish_one_time_prekeys(
    existing_x25519: list[X25519OneTimePrekey],
    existing_kem:    list[KEMOneTimePrekey],
    target_count:    int = OPK_COUNT,
) -> tuple[list[X25519OneTimePrekey], list[KEMOneTimePrekey]]:
    """
    Generate additional OPK pairs to bring the total back up to target_count.
    New OPK IDs continue from the highest existing ID to avoid collisions.

    Returns (new_x25519_opks, new_kem_opks) — both empty if already at target.
    """
    if not existing_x25519:
        return generate_one_time_prekeys(count=target_count, start_id=1)

    highest_id = max(opk.opk_id for opk in existing_x25519)
    shortfall  = target_count - len(existing_x25519)

    if shortfall <= 0:
        return [], []

    return generate_one_time_prekeys(count=shortfall, start_id=highest_id + 1)
