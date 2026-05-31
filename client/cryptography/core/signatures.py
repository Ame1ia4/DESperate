"""
core/signatures.py

Explicit hybrid Ed25519 + ML-DSA-87 signatures over ciphertext, layered on top
of the Double Ratchet. The DR provides implicit authentication but a compromised
server can inject ciphertexts; these signatures prevent that.

Ciphertext is signed (not plaintext) so verification can happen before decryption —
the required call order is verify_ciphertext() → aead.decrypt().

Serialization uses msgpack, which length-prefixes every field internally, preventing
substitution attacks the same way the previous manual LP() encoding did.

sig_input:   msgpack array [ciphertext, aad, sender_id, recipient_id, message_index]
Wire format: msgpack array [sender_id, recipient_id, message_index, signature, ciphertext]

References:
  FIPS 186-5 / RFC 8032 (Ed25519):  https://doi.org/10.6028/NIST.FIPS.186-5
  FIPS 204 (ML-DSA-87):             https://doi.org/10.6028/NIST.FIPS.204
  Signal Double Ratchet:             https://signal.org/docs/specifications/doubleratchet/
"""

from __future__ import annotations

import hmac
import msgpack
from dataclasses import dataclass
from typing import Optional

from core.constants import HYBRID_SIGNATURE_LEN
from core.keys import (
    MalformedSignedCiphertextError,
    SigningKeypair,
    verify_hybrid_signature,
)


# ── Exceptions ────────────────────────────────────────────────────────────────

class SignatureVerificationError(Exception):
    """
    Raised when signature verification fails for any reason.

    The error message is deliberately uniform across all failure modes
    (bad signature, wrong key, malformed input, TOFU mismatch) to prevent
    oracle attacks that distinguish failure causes.

    The receiver must discard the message and must NOT decrypt the ciphertext.
    """

# MalformedSignedCiphertextError is defined in core.keys and re-exported here
# so callers can catch it from either module without a cross-import dependency.


# ── Signature input construction ─────────────────────────────────────────────

def build_sig_input(
    ciphertext:    bytes,
    aad:           bytes,
    sender_id:     bytes,
    recipient_id:  bytes,
    message_index: int,
) -> bytes:
    """
    Construct the canonical byte string that is signed and verified.
    msgpack encodes each field with its type and length, preventing substitution attacks.
    """
    if not (0 <= message_index < 2**64):
        raise ValueError("message_index must be a uint64")
    return msgpack.packb([ciphertext, aad, sender_id, recipient_id, message_index])


# ── SignedCiphertext dataclass ────────────────────────────────────────────────

@dataclass
class SignedCiphertext:
    """
    A ciphertext with a hybrid Ed25519 + ML-DSA-87 signature.

    aad is NOT stored — the receiver reconstructs it from session context,
    matching how the AEAD layer handles it.
    """
    ciphertext:    bytes
    signature:     bytes   # HYBRID_SIGNATURE_LEN bytes: ed25519_sig || ml_dsa_sig
    sender_id:     bytes
    recipient_id:  bytes
    message_index: int

    def __post_init__(self) -> None:
        if len(self.signature) != HYBRID_SIGNATURE_LEN:
            raise MalformedSignedCiphertextError(
                f"signature must be {HYBRID_SIGNATURE_LEN} bytes, got {len(self.signature)}."
            )

    def to_bytes(self) -> bytes:
        """Serialise to wire format: msgpack array [sender_id, recipient_id, message_index, signature, ciphertext]."""
        return msgpack.packb([
            self.sender_id, self.recipient_id,
            self.message_index, self.signature, self.ciphertext,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedCiphertext:
        """Parse wire format produced by to_bytes(). Raises MalformedSignedCiphertextError on any structural problem."""
        try:
            sender_id, recipient_id, message_index, signature, ciphertext = msgpack.unpackb(data)
        except Exception as exc:
            raise MalformedSignedCiphertextError(f"Failed to parse payload: {exc}") from exc
        if len(signature) != HYBRID_SIGNATURE_LEN:
            raise MalformedSignedCiphertextError(
                f"sig_len={len(signature)} but expected {HYBRID_SIGNATURE_LEN}. "
                "Payload may be from an incompatible client version."
            )
        if not ciphertext:
            raise MalformedSignedCiphertextError("Ciphertext is empty.")
        return cls(
            ciphertext=ciphertext, signature=signature,
            sender_id=sender_id, recipient_id=recipient_id, message_index=message_index,
        )


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_ciphertext(
    signing_keypair: SigningKeypair,
    ciphertext:      bytes,
    aad:             bytes,
    sender_id:       bytes,
    recipient_id:    bytes,
    message_index:   int,
) -> SignedCiphertext:
    """
    Sign a ciphertext with the sender's hybrid Ed25519 + ML-DSA-87 keypair.
    Call AFTER aead.encrypt() and BEFORE passing to the transport layer.
    """
    sig_input = build_sig_input(
        ciphertext=ciphertext, aad=aad,
        sender_id=sender_id, recipient_id=recipient_id, message_index=message_index,
    )
    return SignedCiphertext(
        ciphertext=ciphertext, signature=signing_keypair.sign(sig_input),
        sender_id=sender_id, recipient_id=recipient_id, message_index=message_index,
    )


# ── Verification ──────────────────────────────────────────────────────────────

def verify_ciphertext(
    signed:       SignedCiphertext,
    aad:          bytes,
    ik_sig_pub:   bytes,
    expected_pub: Optional[bytes] = None,
) -> None:
    """
    Verify a hybrid signature over a SignedCiphertext.
    MUST be called BEFORE aead.decrypt(). Raises SignatureVerificationError on any failure.

    expected_pub: optional locally pinned key for TOFU enforcement. Compared in constant
    time — a mismatch raises the same error as a bad signature to prevent timing oracles.
    """
    if expected_pub is not None:
        if not hmac.compare_digest(expected_pub, ik_sig_pub):
            raise SignatureVerificationError("Signature verification failed.")

    sig_input = build_sig_input(
        ciphertext=signed.ciphertext, aad=aad,
        sender_id=signed.sender_id, recipient_id=signed.recipient_id,
        message_index=signed.message_index,
    )

    try:
        valid = verify_hybrid_signature(sig_input, signed.signature, ik_sig_pub)
    except MalformedSignedCiphertextError:
        raise
    except Exception:
        raise SignatureVerificationError("Signature verification failed.")

    if not valid:
        raise SignatureVerificationError("Signature verification failed.")


# ── Convenience: verify and extract ──────────────────────────────────────────

def verify_and_extract(
    data:         bytes,
    aad:          bytes,
    ik_sig_pub:   bytes,
    expected_pub: Optional[bytes] = None,
) -> SignedCiphertext:
    """
    Parse wire bytes, verify the hybrid signature, and return the SignedCiphertext.
    Enforces call order: from_bytes() → verify_ciphertext() → return for aead.decrypt().

    Raises MalformedSignedCiphertextError if unparseable, SignatureVerificationError if invalid.
    """
    signed = SignedCiphertext.from_bytes(data)
    verify_ciphertext(signed=signed, aad=aad, ik_sig_pub=ik_sig_pub, expected_pub=expected_pub)
    return signed
