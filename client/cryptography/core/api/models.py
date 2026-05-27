"""
models.py — Payload schemas for the secure messaging API.

These are pure data models. They validate incoming data and serialise
outbound payloads into dicts that the C++ TLS layer can POST to the server.

Usage:
    from models import RegistrationBundle, MessagePayload, ChallengeRequest, VerifyRequest

    bundle = RegistrationBundle(username="alice", password="...", device=DeviceBundle(...))
    bundle.model_dump()   # → dict ready to hand to C++
"""

from __future__ import annotations

import base64
import re
from typing import Optional

from pydantic import BaseModel, field_validator, model_validator

# ── Helpers ──────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    """Encode bytes to a base64 string."""
    return base64.b64encode(data).decode()


def _check_b64(v: str, field: str) -> str:
    """Validate that a string is non-empty base64."""
    if not v:
        raise ValueError(f"{field} must not be empty")
    try:
        base64.b64decode(v, validate=True)
    except Exception:
        raise ValueError(f"{field} must be valid base64")
    return v


# ── Key size constants (bytes, matching auth.js) ──────────────────────────────

_X25519_BYTES     = 32
_ED25519_SIG      = 64
_SIGNING_PUB      = 1984   # 32 (Ed25519) + 1952 (ML-DSA-65)
_MLDSA_SIG        = 3309   # ml_dsa65.signatureLen
_DUAL_SIG         = _ED25519_SIG + _MLDSA_SIG
_MLKEM_PUB        = 1184   # ml_kem768.publicKeyLen
_NONCE_BYTES      = 12     # ChaCha20-Poly1305 nonce


def _check_b64_len(v: str, expected_bytes: int, field: str) -> str:
    """Validate base64 string decodes to exactly expected_bytes."""
    _check_b64(v, field)
    decoded = base64.b64decode(v)
    if len(decoded) != expected_bytes:
        raise ValueError(
            f"{field}: expected {expected_bytes} bytes, got {len(decoded)}"
        )
    return v


# ── Username / password rules (mirrors auth.js) ───────────────────────────────

_USERNAME_RE  = re.compile(r"^[a-zA-Z0-9_]+$")
_USERNAME_MIN = 3
_USERNAME_MAX = 50
_PASSWORD_MIN = 12


# ── Device bundle ─────────────────────────────────────────────────────────────

class DeviceBundle(BaseModel):
    """
    Public key material uploaded to the server during registration.
    All binary fields are base64-encoded strings.
    Private keys never appear here — they stay in state_store.py.
    """

    device_name:              Optional[str] = None

    # Classical identity key (X25519, 32 bytes)
    idk_classical_pub:        str

    # Optional hybrid PQ identity key (ML-KEM-768, 1184 bytes)
    idk_pq_pub:               Optional[str] = None

    # Dual signing public key: Ed25519 (32 b) || ML-DSA-65 (1952 b) = 1984 bytes
    identity_signing_pub:     str

    # SHA-256 hex fingerprint of idk_pub || signing_pub — for TOFU pinning
    identity_fingerprint:     str

    # Signed prekey: X25519 public + dual signature over it
    signed_prekey_pub:        str
    signed_prekey_signature:  str   # Ed25519 sig (64 b) || ML-DSA sig (3309 b)

    # Last-resort OPK — used when all one-time prekeys are exhausted
    last_resort_opk_pub:      Optional[str] = None
    last_resort_opk_signature: Optional[str] = None

    # Batch of one-time prekeys (X25519, up to 100)
    one_time_prekeys:         list[str]

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("device_name")
    @classmethod
    def device_name_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 100:
            raise ValueError("device_name must be 100 characters or fewer")
        return v

    @field_validator("idk_classical_pub")
    @classmethod
    def validate_idk_classical(cls, v: str) -> str:
        return _check_b64_len(v, _X25519_BYTES, "idk_classical_pub")

    @field_validator("idk_pq_pub")
    @classmethod
    def validate_idk_pq(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return _check_b64_len(v, _MLKEM_PUB, "idk_pq_pub")
        return v

    @field_validator("identity_signing_pub")
    @classmethod
    def validate_signing_pub(cls, v: str) -> str:
        return _check_b64_len(v, _SIGNING_PUB, "identity_signing_pub")

    @field_validator("identity_fingerprint")
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", v):
            raise ValueError("identity_fingerprint must be a 64-char lowercase hex SHA-256")
        return v

    @field_validator("signed_prekey_pub")
    @classmethod
    def validate_spk_pub(cls, v: str) -> str:
        return _check_b64_len(v, _X25519_BYTES, "signed_prekey_pub")

    @field_validator("signed_prekey_signature")
    @classmethod
    def validate_spk_sig(cls, v: str) -> str:
        return _check_b64_len(v, _DUAL_SIG, "signed_prekey_signature")

    @field_validator("last_resort_opk_pub")
    @classmethod
    def validate_lr_opk_pub(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return _check_b64_len(v, _X25519_BYTES, "last_resort_opk_pub")
        return v

    @field_validator("last_resort_opk_signature")
    @classmethod
    def validate_lr_opk_sig(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return _check_b64_len(v, _DUAL_SIG, "last_resort_opk_signature")
        return v

    @field_validator("one_time_prekeys")
    @classmethod
    def validate_opks(cls, v: list[str]) -> list[str]:
        if len(v) > 100:
            raise ValueError("one_time_prekeys: maximum 100 keys per batch")
        for i, key in enumerate(v):
            _check_b64_len(key, _X25519_BYTES, f"one_time_prekeys[{i}]")
        return v

    @model_validator(mode="after")
    def lr_opk_both_or_neither(self) -> DeviceBundle:
        """last_resort_opk_pub and its signature must be provided together."""
        has_pub = self.last_resort_opk_pub is not None
        has_sig = self.last_resort_opk_signature is not None
        if has_pub != has_sig:
            raise ValueError(
                "last_resort_opk_pub and last_resort_opk_signature must both be "
                "provided or both omitted"
            )
        return self

    # ── Convenience constructors ──────────────────────────────────────────────

    @classmethod
    def from_keys(
        cls,
        *,
        idk_priv,
        signing_priv,
        spk_priv,
        spk_sig: bytes,
        opk_privs: list,
        lr_opk_priv=None,
        lr_opk_sig: Optional[bytes] = None,
        idk_pq_priv=None,
        device_name: Optional[str] = None,
    ) -> DeviceBundle:
        """
        Build a DeviceBundle directly from key objects (cryptography library).
        Handles encoding so callers don't have to touch base64.

        Example:
            bundle = DeviceBundle.from_keys(
                idk_priv=idk_priv,
                signing_priv=signing_priv,
                spk_priv=spk_priv,
                spk_sig=spk_sig,
                opk_privs=opks,
                lr_opk_priv=lr_opk_priv,
                lr_opk_sig=lr_opk_sig,
            )
        """
        import hashlib

        raw = lambda key: key.public_key().public_bytes_raw()

        idk_pub_bytes     = raw(idk_priv)
        signing_pub_bytes = signing_priv.public_key().public_bytes_raw()
        fingerprint       = hashlib.sha256(idk_pub_bytes + signing_pub_bytes).hexdigest()

        return cls(
            device_name              = device_name,
            idk_classical_pub        = _b64(idk_pub_bytes),
            idk_pq_pub               = _b64(raw(idk_pq_priv)) if idk_pq_priv else None,
            identity_signing_pub     = _b64(signing_pub_bytes),
            identity_fingerprint     = fingerprint,
            signed_prekey_pub        = _b64(raw(spk_priv)),
            signed_prekey_signature  = _b64(spk_sig),
            last_resort_opk_pub      = _b64(raw(lr_opk_priv)) if lr_opk_priv else None,
            last_resort_opk_signature= _b64(lr_opk_sig) if lr_opk_sig else None,
            one_time_prekeys         = [_b64(raw(opk)) for opk in opk_privs],
        )


# ── Registration ──────────────────────────────────────────────────────────────

class RegistrationBundle(BaseModel):
    """
    Full payload for POST /auth/register.
    Wraps credentials + device key bundle.
    """

    username: str
    password: str
    device:   DeviceBundle

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not _USERNAME_MIN <= len(v) <= _USERNAME_MAX:
            raise ValueError(
                f"username must be {_USERNAME_MIN}–{_USERNAME_MAX} characters"
            )
        if not _USERNAME_RE.fullmatch(v):
            raise ValueError("username may only contain letters, digits, and underscores")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < _PASSWORD_MIN:
            raise ValueError(f"password must be at least {_PASSWORD_MIN} characters")
        return v

    def to_payload(self) -> dict:
        """
        Return a JSON-serialisable dict for the C++ layer to POST.
        device.one_time_prekeys is kept as a flat list of base64 strings,
        matching what the server's /auth/register route expects.
        """
        return self.model_dump()


# ── Auth ──────────────────────────────────────────────────────────────────────

class ChallengeRequest(BaseModel):
    """Payload for POST /auth/challenge."""

    device_id: str

    @field_validator("device_id")
    @classmethod
    def non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("device_id must not be empty")
        return v

    def to_payload(self) -> dict:
        return self.model_dump()


class VerifyRequest(BaseModel):
    """
    Payload for POST /auth/verify.
    Both signatures are over the nonce bytes returned by /auth/challenge.
    """

    device_id:    str
    ed25519_sig:  str   # 64 bytes, base64
    ml_dsa_sig:   str   # 3309 bytes, base64

    @field_validator("device_id")
    @classmethod
    def non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("device_id must not be empty")
        return v

    @field_validator("ed25519_sig")
    @classmethod
    def validate_ed_sig(cls, v: str) -> str:
        return _check_b64_len(v, _ED25519_SIG, "ed25519_sig")

    @field_validator("ml_dsa_sig")
    @classmethod
    def validate_mldsa_sig(cls, v: str) -> str:
        return _check_b64_len(v, _MLDSA_SIG, "ml_dsa_sig")

    @classmethod
    def from_signatures(
        cls,
        *,
        device_id: str,
        ed25519_sig: bytes,
        ml_dsa_sig: bytes,
    ) -> VerifyRequest:
        """Build from raw signature bytes."""
        return cls(
            device_id   = device_id,
            ed25519_sig = _b64(ed25519_sig),
            ml_dsa_sig  = _b64(ml_dsa_sig),
        )

    def to_payload(self) -> dict:
        return self.model_dump()


# ── X3DH header (first message only) ─────────────────────────────────────────

class X3DHHeader(BaseModel):
    """
    Included only in the first message of a conversation.
    Lets the recipient reconstruct the shared secret without a prior exchange.
    """

    alice_idk_pub: str   # Alice's X25519 identity key pub, base64 (32 bytes)
    alice_eph_pub: str   # Alice's ephemeral X25519 pub, base64 (32 bytes)
    bob_opk_id:    Optional[str] = None  # ID of the OPK used; None if last-resort

    @field_validator("alice_idk_pub")
    @classmethod
    def validate_alice_idk(cls, v: str) -> str:
        return _check_b64_len(v, _X25519_BYTES, "alice_idk_pub")

    @field_validator("alice_eph_pub")
    @classmethod
    def validate_alice_eph(cls, v: str) -> str:
        return _check_b64_len(v, _X25519_BYTES, "alice_eph_pub")

    @classmethod
    def from_keys(
        cls,
        *,
        idk_priv,
        eph_priv,
        bob_opk_id: Optional[str] = None,
    ) -> X3DHHeader:
        return cls(
            alice_idk_pub = _b64(idk_priv.public_key().public_bytes_raw()),
            alice_eph_pub = _b64(eph_priv.public_key().public_bytes_raw()),
            bob_opk_id    = bob_opk_id,
        )


# ── Message payload ───────────────────────────────────────────────────────────

class MessagePayload(BaseModel):
    """
    Payload for POST /messages.

    ciphertext, nonce, and associated_data are all base64.
    x3dh_header is only present for the first message in a conversation.
    """

    conversation_id:  str
    recipient_device: str          # device_id of the intended recipient

    ciphertext:       str          # ChaCha20-Poly1305 ciphertext, base64
    nonce:            str          # 12-byte nonce, base64
    associated_data:  str          # conversation_id || sender_device_id, base64

    x3dh_header:      Optional[X3DHHeader] = None

    @field_validator("conversation_id", "recipient_device")
    @classmethod
    def non_empty_str(cls, v: str) -> str:
        if not v:
            raise ValueError("field must not be empty")
        return v

    @field_validator("ciphertext", "associated_data")
    @classmethod
    def valid_b64(cls, v: str) -> str:
        return _check_b64(v, "field")

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, v: str) -> str:
        return _check_b64_len(v, _NONCE_BYTES, "nonce")

    @classmethod
    def build(
        cls,
        *,
        conversation_id: str,
        recipient_device: str,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes,
        x3dh_header: Optional[X3DHHeader] = None,
    ) -> MessagePayload:
        """
        Build from raw bytes — no manual base64 encoding needed.

        Example (from crypto_notes step 5):
            payload = MessagePayload.build(
                conversation_id  = str(conversation_id),
                recipient_device = bob_device_id,
                ciphertext       = ciphertext,
                nonce            = nonce,
                associated_data  = aad,
                x3dh_header      = X3DHHeader.from_keys(
                    idk_priv    = idk_priv,
                    eph_priv    = eph_priv,
                    bob_opk_id  = bob_bundle["opk_id"],
                ) if first_message else None,
            )
            payload.to_payload()  # → dict for C++
        """
        return cls(
            conversation_id  = conversation_id,
            recipient_device = recipient_device,
            ciphertext       = _b64(ciphertext),
            nonce            = _b64(nonce),
            associated_data  = _b64(associated_data),
            x3dh_header      = x3dh_header,
        )

    def to_payload(self) -> dict:
        """
        Return a JSON-serialisable dict for the C++ layer to POST to /messages.
        x3dh_header is omitted entirely if None (not sent as null).
        """
        d = self.model_dump(exclude_none=True)
        return d
