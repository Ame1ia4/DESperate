"""
core/keys.py

PQXDH key bundle generation.

Generates and manages cryptographic identity material for each user:
  - ML-KEM-1024  identity keypair               (key encapsulation, NIST FIPS 203 level 5)
  - Ed25519 + ML-DSA-87  signing keypair        (hybrid signatures, FIPS 186-5 + FIPS 204)
  - X25519       identity keypair               (classical DH leg of hybrid PQXDH)
  - X25519       signed prekey                  (SPK, rotated periodically)
  - X25519       one-time prekeys               (classical DH4 leg per session)
  - ML-KEM-1024  one-time prekeys               (PQ encapsulation leg per session)

Each PQXDH session initiation consumes one X25519 OPK (for DH4) and one
ML-KEM OPK (for PQ encapsulation). Both are identified by the same opk_id
so the responder can look up both secret keys from a single index.

INVARIANT: x25519_opks and kem_opks must always have the same length and
matching opk_ids at every index. All generation and replenishment functions
enforce this — callers must never modify either list independently.

Key sizes (NIST level 5):
  ML-KEM-1024  public key : 1568 bytes
  ML-KEM-1024  secret key : 3168 bytes
  ML-KEM-1024  ciphertext : 1568 bytes
  ML-DSA-87    public key : 2592 bytes
  ML-DSA-87    secret key : 4896 bytes
  ML-DSA-87    signature  : 4627 bytes
  Ed25519      public key :   32 bytes
  Ed25519      secret key :   32 bytes
  X25519       public key :   32 bytes
  X25519       secret key :   32 bytes
  Hybrid sig public key   : 2624 bytes  (ed25519_pub || ml_dsa_pub)
  Hybrid signature        : 4691 bytes  (ed25519_sig || ml_dsa_sig)

References:
  PQXDH specification: https://signal.org/docs/specifications/pqxdh/
  FIPS 203 (ML-KEM):   https://doi.org/10.6028/NIST.FIPS.203
  FIPS 204 (ML-DSA):   https://doi.org/10.6028/NIST.FIPS.204
  RFC 7748 (X25519):   https://www.rfc-editor.org/rfc/rfc7748
"""

from __future__ import annotations

from dataclasses import dataclass, field

import oqs

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
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
    ED25519_PUBLIC_KEY_LEN,
    ED25519_SIGNATURE_LEN,
    HYBRID_PUBLIC_KEY_LEN,
    HYBRID_SIGNATURE_LEN,
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
            f"{KEM_ALG} public key: expected {KEM_PUBLIC_KEY_LEN}, got {len(pub)}"
        assert len(ct) == KEM_CIPHERTEXT_LEN, \
            f"{KEM_ALG} ciphertext: expected {KEM_CIPHERTEXT_LEN}, got {len(ct)}"

    with oqs.Signature(SIG_ALG) as sig:
        pub = sig.generate_keypair()
        s   = sig.sign(b"probe")
        assert len(pub) == DSA_PUBLIC_KEY_LEN, \
            f"{SIG_ALG} public key: expected {DSA_PUBLIC_KEY_LEN}, got {len(pub)}"
        assert len(s) == DSA_SIGNATURE_LEN, \
            f"{SIG_ALG} signature: expected {DSA_SIGNATURE_LEN}, got {len(s)}"


# ── OPK pair invariant enforcement ───────────────────────────────────────────

def _assert_opk_lists_valid(
    x25519_opks: list[X25519OneTimePrekey],
    kem_opks:    list[KEMOneTimePrekey],
    context:     str = "",
) -> None:
    """
    Enforce the OPK pairing invariant:
      - Both lists must have the same length.
      - opk_id must match at every index.

    Raises AssertionError immediately on any violation so callers surface
    state corruption rather than silently producing mismatched bundles.
    """
    prefix = f"[{context}] " if context else ""
    assert len(x25519_opks) == len(kem_opks), (
        f"{prefix}OPK list length mismatch: "
        f"x25519_opks={len(x25519_opks)}, kem_opks={len(kem_opks)}. "
        f"Lists must always be generated and modified together."
    )
    for i, (x_opk, k_opk) in enumerate(zip(x25519_opks, kem_opks)):
        assert x_opk.opk_id == k_opk.opk_id, (
            f"{prefix}OPK ID mismatch at index {i}: "
            f"x25519_opks[{i}].opk_id={x_opk.opk_id}, "
            f"kem_opks[{i}].opk_id={k_opk.opk_id}. "
            f"Both lists must share opk_ids at matching indexes."
        )


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
    """
    Hybrid Ed25519 + ML-DSA-87 signing keypair.

    public_key        : 2624-byte hybrid public key (ed25519_pub || ml_dsa87_pub)
    secret_key        : ML-DSA-87 secret key (4896 bytes)
    ed25519_secret_key: Ed25519 private key bytes (32 bytes)

    Both secret keys never leave the device.
    """
    public_key:         bytes   # 2624 bytes: ed25519_pub (32) || ml_dsa87_pub (2592)
    secret_key:         bytes   # ML-DSA-87 secret key (4896 bytes)
    ed25519_secret_key: bytes   # Ed25519 private key (32 bytes)

    def sign(self, message: bytes) -> bytes:
        """Sign message. Returns hybrid 4691-byte signature (ed25519_sig || ml_dsa87_sig)."""
        ed_priv = Ed25519PrivateKey.from_private_bytes(self.ed25519_secret_key)
        ed_sig  = ed_priv.sign(message)
        with oqs.Signature(SIG_ALG, self.secret_key) as signer:
            dsa_sig = signer.sign(message)
        return ed_sig + dsa_sig

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
    A single X25519 one-time prekey (OPK) for the classical DH4 leg of PQXDH.
    Paired with a KEMOneTimePrekey of the same opk_id for the PQ leg.
    """
    opk_id:     int
    public_key: bytes   # 32 bytes (X25519)
    secret_key: bytes   # 32 bytes (X25519)

    def __repr__(self) -> str:
        return f"X25519OneTimePrekey(id={self.opk_id}, public={self.public_key.hex()[:16]}…)"


@dataclass
class KEMOneTimePrekey:
    """
    A single ML-KEM-1024 one-time prekey (OPK) for the PQ encapsulation leg
    of PQXDH.

    Paired with an X25519OneTimePrekey of the same opk_id for the classical
    DH4 leg. opk_id must match the corresponding X25519OneTimePrekey opk_id.
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
    Signed by the user's hybrid Ed25519 + ML-DSA-87 identity key.
    Rotation policy: rotate weekly (PQXDH spec §3.3).
    """
    spk_id:    int
    keypair:   X25519Keypair
    signature: bytes   # hybrid 4691-byte signature over keypair.public_key_bytes

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

    INVARIANT: x25519_opks and kem_opks must have the same length and
    matching opk_ids at every index. Use generate_identity_bundle() and
    replenish_one_time_prekeys() to modify these lists — never mutate
    them independently.

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

    def __post_init__(self) -> None:
        _assert_opk_lists_valid(self.x25519_opks, self.kem_opks, "IdentityBundle.__post_init__")

    def to_public_bundle(self) -> dict:
        """
        Serialise the public half of this bundle for upload to the server.
        No private key material is included.

        OPKs are serialised in two parallel lists (opks_x25519, opks_kem).
        Both lists are guaranteed to have matching opk_ids at every index.
        """
        _assert_opk_lists_valid(self.x25519_opks, self.kem_opks, "to_public_bundle")

        x25519_list = [
            {"opk_id": opk.opk_id, "opk_pub": opk.public_key.hex()}
            for opk in self.x25519_opks
        ]
        kem_list = [
            {"opk_id": opk.opk_id, "opk_pub": opk.public_key.hex()}
            for opk in self.kem_opks
        ]
        return {
            "user_id":          self.user_id,
            "ik_kem_pub":       self.ik_kem.public_key.hex(),
            "ik_sig_pub":       self.ik_sig.public_key.hex(),
            "ik_classical_pub": self.ik_classical.public_key_bytes.hex(),
            "spk_id":           self.spk.spk_id,
            "spk_pub":          self.spk.keypair.public_key_bytes.hex(),
            "spk_sig":          self.spk.signature.hex(),
            "opks_x25519":      x25519_list,
            "opks_kem":         kem_list,
        }

    def to_private_bundle(self) -> dict:
        """
        Serialise the full bundle including private keys for encrypted
        local storage. Never store this output in plaintext.

        OPKs are serialised in two parallel lists (opks_x25519, opks_kem)
        with matching opk_ids. Load both lists when restoring from storage.
        """
        _assert_opk_lists_valid(self.x25519_opks, self.kem_opks, "to_private_bundle")

        return {
            "user_id":          self.user_id,
            "ik_kem_pub":       self.ik_kem.public_key.hex(),
            "ik_kem_sec":       self.ik_kem.secret_key.hex(),
            "ik_sig_pub":           self.ik_sig.public_key.hex(),
            "ik_sig_sec":           self.ik_sig.secret_key.hex(),
            "ik_sig_ed25519_sec":   self.ik_sig.ed25519_secret_key.hex(),
            "ik_classical_pub": self.ik_classical.public_key_bytes.hex(),
            "ik_classical_sec": self.ik_classical.private_key_bytes.hex(),
            "spk_id":           self.spk.spk_id,
            "spk_pub":          self.spk.keypair.public_key_bytes.hex(),
            "spk_sec":          self.spk.keypair.private_key_bytes.hex(),
            "spk_sig":          self.spk.signature.hex(),
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
    """Generate a fresh hybrid Ed25519 + ML-DSA-87 signing keypair."""
    ed_priv      = Ed25519PrivateKey.generate()
    ed_pub_bytes = ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ed_sec_bytes = ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    with oqs.Signature(SIG_ALG) as sig:
        dsa_pub = sig.generate_keypair()
        dsa_sec = sig.export_secret_key()
    return SigningKeypair(
        public_key         = ed_pub_bytes + dsa_pub,
        secret_key         = dsa_sec,
        ed25519_secret_key = ed_sec_bytes,
    )


def generate_signed_prekey(
    signing_keypair: SigningKeypair,
    spk_id: int = 1,
) -> SignedPrekey:
    """
    Generate a fresh X25519 signed prekey.
    The SPK public key is signed with the user's hybrid Ed25519 + ML-DSA-87 identity key.
    """
    spk_keypair = X25519Keypair.generate()
    signature   = signing_keypair.sign(spk_keypair.public_key_bytes)
    return SignedPrekey(
        spk_id    = spk_id,
        keypair   = spk_keypair,
        signature = signature,
    )


def generate_x25519_one_time_prekeys(
    count:    int,
    start_id: int = 1,
) -> list[X25519OneTimePrekey]:
    """Generate a batch of X25519 one-time prekeys (classical DH4 leg)."""
    result = []
    for i in range(count):
        opk_id = start_id + i
        kp = X25519Keypair.generate()
        result.append(X25519OneTimePrekey(
            opk_id     = opk_id,
            public_key = kp.public_key_bytes,
            secret_key = kp.private_key_bytes,
        ))
    return result


def generate_kem_one_time_prekeys(
    count:    int = OPK_COUNT,
    start_id: int = 1,
) -> list[KEMOneTimePrekey]:
    """
    Generate a batch of ML-KEM-1024 one-time prekeys (PQ encapsulation leg).
    Each OPK is consumed by exactly one PQXDH session initiation.
    The server must not reuse OPKs — if no OPKs remain, the initiator
    falls back to the identity key (reduced PQ forward secrecy).
    """
    result = []
    for i in range(count):
        opk_id = start_id + i
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            pub = kem.generate_keypair()
            sec = kem.export_secret_key()
        result.append(KEMOneTimePrekey(
            opk_id     = opk_id,
            public_key = pub,
            secret_key = sec,
        ))
    return result


def generate_opk_pairs(
    count:    int = OPK_COUNT,
    start_id: int = 1,
) -> tuple[list[X25519OneTimePrekey], list[KEMOneTimePrekey]]:
    """
    Generate a matched batch of (X25519, ML-KEM) OPK pairs.

    Always use this function when generating OPKs — never call
    generate_x25519_one_time_prekeys and generate_kem_one_time_prekeys
    separately, as that risks producing lists with different lengths or
    mismatched IDs.

    Returns (x25519_opks, kem_opks) with identical opk_ids at every index.
    """
    x25519_opks = generate_x25519_one_time_prekeys(count=count, start_id=start_id)
    kem_opks    = generate_kem_one_time_prekeys(count=count, start_id=start_id)
    _assert_opk_lists_valid(x25519_opks, kem_opks, "generate_opk_pairs")
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
    ik_kem       = generate_kem_keypair()
    ik_sig       = generate_signing_keypair()
    ik_classical = X25519Keypair.generate()
    spk          = generate_signed_prekey(ik_sig, spk_id=1)
    x25519_opks, kem_opks = generate_opk_pairs(count=opk_count, start_id=1)

    return IdentityBundle(
        user_id      = user_id,
        ik_kem       = ik_kem,
        ik_sig       = ik_sig,
        ik_classical = ik_classical,
        spk          = spk,
        x25519_opks  = x25519_opks,
        kem_opks     = kem_opks,
    )


class MalformedSignedCiphertextError(Exception):
    """
    Raised when a hybrid-signed payload is structurally invalid —
    wrong key or signature length, or bytes that cannot be parsed.

    Distinct from a bad-signature failure: the bytes cannot even be
    interpreted, not that verification failed on valid-looking input.
    """


def verify_hybrid_signature(
    message:    bytes,
    signature:  bytes,
    ik_sig_pub: bytes,
) -> bool:
    """
    Verify a hybrid Ed25519 + ML-DSA-87 signature over arbitrary message bytes.

    Both algorithms must verify independently. Returns False if either fails.
    Raises MalformedSignedCiphertextError if ik_sig_pub or signature is the
    wrong length (structural error, not a crypto failure).

    Parameters
    ----------
    message    : the exact bytes that were signed
    signature  : 4691-byte hybrid signature (ed25519_sig (64) || ml_dsa87_sig (4627)),
                 or 4627-byte legacy ML-DSA-87-only signature (transition window)
    ik_sig_pub : 2624-byte hybrid public key (ed25519_pub (32) || ml_dsa87_pub (2592)),
                 or 2592-byte legacy ML-DSA-87-only key (transition window)

    Transition window
    -----------------
    Users registered before the hybrid-signature PR have a 2592-byte ML-DSA-87-only
    ik_sig_pub on the server. For those keys, Ed25519 verification is skipped and only
    ML-DSA-87 is verified. Remove this branch once all users have re-registered.
    """
    if len(ik_sig_pub) == HYBRID_PUBLIC_KEY_LEN:
        if len(signature) != HYBRID_SIGNATURE_LEN:
            raise MalformedSignedCiphertextError(
                f"signature must be {HYBRID_SIGNATURE_LEN} bytes for a hybrid key, "
                f"got {len(signature)}."
            )
        ed_pub_bytes  = ik_sig_pub[:ED25519_PUBLIC_KEY_LEN]
        dsa_pub_bytes = ik_sig_pub[ED25519_PUBLIC_KEY_LEN:]
        ed_sig        = signature[:ED25519_SIGNATURE_LEN]
        dsa_sig       = signature[ED25519_SIGNATURE_LEN:]

        try:
            Ed25519PublicKey.from_public_bytes(ed_pub_bytes).verify(ed_sig, message)
        except Exception:
            return False

        try:
            with oqs.Signature(SIG_ALG) as verifier:
                if not verifier.verify(message, dsa_sig, dsa_pub_bytes):
                    return False
        except Exception:
            return False

        return True

    elif len(ik_sig_pub) == DSA_PUBLIC_KEY_LEN:
        # Legacy ML-DSA-87-only key — transition window, Ed25519 leg unavailable.
        if len(signature) == DSA_SIGNATURE_LEN:
            dsa_sig = signature
        elif len(signature) == HYBRID_SIGNATURE_LEN:
            dsa_sig = signature[ED25519_SIGNATURE_LEN:]
        else:
            raise MalformedSignedCiphertextError(
                f"signature must be {DSA_SIGNATURE_LEN} or {HYBRID_SIGNATURE_LEN} bytes "
                f"for a legacy key, got {len(signature)}."
            )

        try:
            with oqs.Signature(SIG_ALG) as verifier:
                return verifier.verify(message, dsa_sig, ik_sig_pub)
        except Exception:
            return False

    else:
        raise MalformedSignedCiphertextError(
            f"ik_sig_pub must be {HYBRID_PUBLIC_KEY_LEN} (hybrid) or "
            f"{DSA_PUBLIC_KEY_LEN} (legacy) bytes, got {len(ik_sig_pub)}."
        )


def verify_spk_signature(
    spk_pub:    bytes,
    signature:  bytes,
    ik_sig_pub: bytes,
) -> bool:
    """
    Verify that an SPK was signed by the expected hybrid Ed25519 + ML-DSA-87 identity key.
    Returns True if both signatures are valid. Returns False for a cryptographic failure.
    Both algorithms must verify independently; neither alone is sufficient.

    Raises MalformedSignedCiphertextError if ik_sig_pub or signature is structurally invalid
    (wrong length, corrupt key from server). Callers must distinguish this from a False return,
    which indicates a genuine signature failure on well-formed input.
    """
    return verify_hybrid_signature(spk_pub, signature, ik_sig_pub)


def replenish_one_time_prekeys(
    existing_x25519: list[X25519OneTimePrekey],
    existing_kem:    list[KEMOneTimePrekey],
    target_count:    int = OPK_COUNT,
) -> tuple[list[X25519OneTimePrekey], list[KEMOneTimePrekey]]:
    """
    Generate additional OPK pairs to bring the total back up to target_count.

    New OPK IDs continue from the highest existing ID across both lists
    to avoid collisions regardless of which list consumed more keys.

    Returns (new_x25519_opks, new_kem_opks) — both empty lists if already
    at or above target_count.

    Raises
    ------
    AssertionError : if existing_x25519 and existing_kem have different
                     lengths or mismatched opk_ids — indicates state
                     corruption that must be resolved before replenishing.
    """
    both_empty = not existing_x25519 and not existing_kem

    if both_empty:
        return generate_opk_pairs(count=target_count, start_id=1)

    # Validate existing state before deriving anything from it
    _assert_opk_lists_valid(existing_x25519, existing_kem, "replenish_one_time_prekeys")

    # Derive highest_id across both lists — guards against the case where
    # one list has consumed more keys than the other
    highest_x25519 = max((opk.opk_id for opk in existing_x25519), default=0)
    highest_kem    = max((opk.opk_id for opk in existing_kem),    default=0)
    highest_id     = max(highest_x25519, highest_kem)

    # Shortfall is based on the shorter list — conservative, avoids over-generating
    current_count = min(len(existing_x25519), len(existing_kem))
    shortfall     = target_count - current_count

    if shortfall <= 0:
        return [], []

    return generate_opk_pairs(count=shortfall, start_id=highest_id + 1)
