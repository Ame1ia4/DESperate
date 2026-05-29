"""
core/signatures.py

Hybrid Ed25519 + ML-DSA-87 explicit message signing over ciphertext.

WHY SIGN CIPHERTEXT, NOT PLAINTEXT
  Signal's Double Ratchet provides implicit authentication — a message can only
  decrypt if it came from someone who holds the correct ratchet state. However,
  a fully compromised server can inject arbitrary ciphertexts into the delivery
  queue. Explicit ML-DSA-87 + Ed25519 signatures over ciphertext mean the server
  cannot forge a message even with full database access, because it does not hold
  the sender's signing private keys.

  Signing ciphertext (not plaintext) is the correct choice:
    - Signing plaintext would require decrypting before verifying, reversing the
      required call order (verify MUST come before decrypt).
    - Signing ciphertext binds the signature to the exact bytes on the wire,
      so any tampering — even a single bit flip — invalidates the signature
      before the AEAD tag is ever checked.

HYBRID SIGNING SCHEME (Ed25519 + ML-DSA-87)
  Both algorithms sign the identical sig_input bytes. Both signatures are
  concatenated on the wire. Both must verify independently — partial
  verification is not accepted. This provides:
    - Classical security from Ed25519 (FIPS 186-5, RFC 8032) today.
    - Post-quantum security from ML-DSA-87 (FIPS 204) against a future
      quantum adversary with Shor's algorithm.
  Neither alone is sufficient — both must be broken simultaneously for
  the scheme to fail.

SIGNATURE INPUT CONSTRUCTION
  sig_input = LP(ciphertext) || LP(aad) || LP(sender_id) || LP(recipient_id)
              || message_index (8 bytes, little-endian uint64)

  where LP(x) = struct.pack("!H", len(x)) + x  (2-byte big-endian length prefix)

  Length-prefixing prevents substitution attacks: without it,
  b"alice" || b"bob" == b"aliceb" || b"ob" as raw bytes. AEAD cannot
  distinguish these; length-prefixed fields make every concatenation unique.
  message_index is fixed-width (8 bytes) so it needs no length prefix.

CALL ORDER ON THE RECEIVE PATH
  verify_ciphertext() MUST be called BEFORE aead.decrypt().
  Decrypting an unauthenticated ciphertext risks oracle attacks even if
  the AEAD tag check follows. Verify first, decrypt only on success.

TOFU PINNING
  verify_ciphertext() accepts an optional expected_pub parameter.
  When provided, it is compared against the sender's locally pinned public
  key in constant time before attempting signature verification. A mismatch
  is treated identically to a bad signature (uniform error) to prevent
  oracle attacks distinguishing "wrong key" from "bad signature".

WIRE FORMAT (SignedCiphertext)
  sender_id_len  (2 bytes, big-endian)
  sender_id      (variable)
  recipient_id_len (2 bytes, big-endian)
  recipient_id   (variable)
  message_index  (8 bytes, little-endian uint64)
  sig_len        (2 bytes, big-endian) — always 4691
  signature      (4691 bytes: ed25519_sig || ml_dsa87_sig)
  ciphertext     (remainder)

  The header fields are also included in the AEAD associated data (aad),
  so tampering with any header field invalidates both the signature and
  the AEAD tag independently.

References:
  FIPS 186-5 (Ed25519):  https://doi.org/10.6028/NIST.FIPS.186-5
  FIPS 204 (ML-DSA-87):  https://doi.org/10.6028/NIST.FIPS.204
  RFC 8032 (Ed25519):    https://www.rfc-editor.org/rfc/rfc8032
  Signal DR spec:        https://signal.org/docs/specifications/doubleratchet/
"""

from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass
from typing import Optional

import oqs

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.keys import (
    SIG_ALG,
    SigningKeypair,
    ED25519_PUBLIC_KEY_LEN,
    ED25519_SIGNATURE_LEN,
    HYBRID_PUBLIC_KEY_LEN,
    HYBRID_SIGNATURE_LEN,
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

class MalformedSignedCiphertextError(Exception):
    """
    Raised when a SignedCiphertext wire payload is structurally invalid —
    too short, inconsistent length fields, or signature length != 4691.

    Distinct from SignatureVerificationError: this means the bytes cannot
    even be parsed, not that parsing succeeded but verification failed.
    """


# ── Wire format constants ────────────────────────────────────────────────────

_LEN_PREFIX_SIZE  = 2          # 2-byte big-endian length prefix used by LP()
_MSG_INDEX_SIZE   = 8          # uint64 little-endian message index
_SIG_LEN_SIZE     = 2          # 2-byte big-endian field storing signature length

# Minimum parseable header: two LP fields (2+0 bytes each) + index + sig_len
_MIN_HEADER_BYTES = (
    _LEN_PREFIX_SIZE +   # sender_id_len
    _LEN_PREFIX_SIZE +   # recipient_id_len
    _MSG_INDEX_SIZE  +   # message_index
    _SIG_LEN_SIZE    +   # sig_len
    HYBRID_SIGNATURE_LEN # signature
)


# ── Signature input construction ─────────────────────────────────────────────

def _lp(data: bytes) -> bytes:
    """
    Length-prefix encode data with a 2-byte big-endian length header.

    Prevents concatenation ambiguity: LP(a) || LP(b) is always unambiguous
    regardless of the content of a and b.

    Raises ValueError if data exceeds 65535 bytes (2-byte length limit).
    """
    if len(data) > 0xFFFF:
        raise ValueError(
            f"Field too long for 2-byte length prefix: {len(data)} bytes "
            f"(max 65535). Consider using a shorter identifier."
        )
    return struct.pack("!H", len(data)) + data


def build_sig_input(
    ciphertext:    bytes,
    aad:           bytes,
    sender_id:     bytes,
    recipient_id:  bytes,
    message_index: int,
) -> bytes:
    """
    Construct the canonical byte string that is signed and verified.

    Layout:
      LP(ciphertext) || LP(aad) || LP(sender_id) || LP(recipient_id)
      || message_index (8 bytes, little-endian uint64)

    All variable-length fields are length-prefixed to prevent substitution
    attacks. message_index is fixed-width and requires no prefix.

    Parameters
    ----------
    ciphertext    : the AEAD ciphertext (reuse_guard || nonce || ct || tag)
    aad           : associated data used in the AEAD encryption
    sender_id     : sender identifier as bytes (e.g. b"alice")
    recipient_id  : recipient identifier as bytes (e.g. b"bob")
    message_index : DR message index (uint64)
    """
    if not (0 <= message_index < 2**64):
        raise ValueError("message_index must be a uint64")

    return (
        _lp(ciphertext)
        + _lp(aad)
        + _lp(sender_id)
        + _lp(recipient_id)
        + struct.pack("<Q", message_index)
    )


# ── SignedCiphertext dataclass ────────────────────────────────────────────────

@dataclass
class SignedCiphertext:
    """
    A ciphertext with a hybrid Ed25519 + ML-DSA-87 signature.

    Fields
    ------
    ciphertext    : AEAD ciphertext bytes (reuse_guard || nonce || ct || tag)
    signature     : 4691-byte hybrid signature (ed25519_sig || ml_dsa87_sig)
    sender_id     : sender identifier bytes
    recipient_id  : recipient identifier bytes
    message_index : DR message index (uint64)

    The signature covers build_sig_input(ciphertext, aad, sender_id,
    recipient_id, message_index) — the aad is NOT stored here because it
    is reconstructed by the receiver from session context. This matches
    how the AEAD layer handles aad.
    """
    ciphertext:    bytes
    signature:     bytes   # 4691 bytes: ed25519_sig (64) || ml_dsa87_sig (4627)
    sender_id:     bytes
    recipient_id:  bytes
    message_index: int

    def __post_init__(self) -> None:
        if len(self.signature) != HYBRID_SIGNATURE_LEN:
            raise MalformedSignedCiphertextError(
                f"signature must be {HYBRID_SIGNATURE_LEN} bytes, "
                f"got {len(self.signature)}. "
                f"Expected ed25519_sig (64) || ml_dsa87_sig (4627)."
            )

    def to_bytes(self) -> bytes:
        """
        Serialise to wire format.

        Layout:
          LP(sender_id) || LP(recipient_id) || message_index (8 B LE)
          || sig_len (2 B BE) || signature (4691 B) || ciphertext
        """
        return (
            _lp(self.sender_id)
            + _lp(self.recipient_id)
            + struct.pack("<Q", self.message_index)
            + struct.pack("!H", len(self.signature))
            + self.signature
            + self.ciphertext
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedCiphertext:
        """
        Parse wire format produced by to_bytes().

        Raises MalformedSignedCiphertextError if the payload is too short,
        length fields are inconsistent, or sig_len != HYBRID_SIGNATURE_LEN.
        """
        offset = 0

        def _read_lp(label: str) -> bytes:
            nonlocal offset
            if offset + _LEN_PREFIX_SIZE > len(data):
                raise MalformedSignedCiphertextError(
                    f"Truncated at {label} length prefix (offset={offset})."
                )
            (field_len,) = struct.unpack_from("!H", data, offset)
            offset += _LEN_PREFIX_SIZE
            if offset + field_len > len(data):
                raise MalformedSignedCiphertextError(
                    f"Truncated at {label} body: "
                    f"need {field_len} bytes at offset {offset}, "
                    f"only {len(data) - offset} available."
                )
            value = data[offset : offset + field_len]
            offset += field_len
            return value

        sender_id    = _read_lp("sender_id")
        recipient_id = _read_lp("recipient_id")

        if offset + _MSG_INDEX_SIZE > len(data):
            raise MalformedSignedCiphertextError(
                f"Truncated at message_index (offset={offset})."
            )
        (message_index,) = struct.unpack_from("<Q", data, offset)
        offset += _MSG_INDEX_SIZE

        if offset + _SIG_LEN_SIZE > len(data):
            raise MalformedSignedCiphertextError(
                f"Truncated at sig_len (offset={offset})."
            )
        (sig_len,) = struct.unpack_from("!H", data, offset)
        offset += _SIG_LEN_SIZE

        if sig_len != HYBRID_SIGNATURE_LEN:
            raise MalformedSignedCiphertextError(
                f"sig_len={sig_len} but expected {HYBRID_SIGNATURE_LEN}. "
                f"Payload may be from an incompatible client version."
            )

        if offset + sig_len > len(data):
            raise MalformedSignedCiphertextError(
                f"Truncated at signature body (offset={offset}, sig_len={sig_len})."
            )
        signature  = data[offset : offset + sig_len]
        offset    += sig_len

        ciphertext = data[offset:]
        if not ciphertext:
            raise MalformedSignedCiphertextError(
                "No ciphertext bytes after signature — payload is empty."
            )

        return cls(
            ciphertext    = ciphertext,
            signature     = signature,
            sender_id     = sender_id,
            recipient_id  = recipient_id,
            message_index = message_index,
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

    Call this AFTER aead.encrypt() and BEFORE handing the payload to the
    transport layer.

    Parameters
    ----------
    signing_keypair : sender's SigningKeypair (holds both private keys)
    ciphertext      : output of aead.encrypt()
    aad             : the same aad passed to aead.encrypt()
    sender_id       : sender identifier bytes
    recipient_id    : recipient identifier bytes
    message_index   : DR message index passed to aead.encrypt()

    Returns
    -------
    SignedCiphertext ready for to_bytes() and transmission.
    """
    sig_input = build_sig_input(
        ciphertext    = ciphertext,
        aad           = aad,
        sender_id     = sender_id,
        recipient_id  = recipient_id,
        message_index = message_index,
    )
    signature = signing_keypair.sign(sig_input)

    return SignedCiphertext(
        ciphertext    = ciphertext,
        signature     = signature,
        sender_id     = sender_id,
        recipient_id  = recipient_id,
        message_index = message_index,
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

    MUST be called BEFORE aead.decrypt(). Raises SignatureVerificationError
    on any failure — the caller must not proceed to decryption.

    Both the Ed25519 and ML-DSA-87 components must verify independently.
    If either fails the entire signature is rejected.

    Parameters
    ----------
    signed       : the SignedCiphertext to verify
    aad          : the associated data the sender used in aead.encrypt().
                   Must be reconstructed from session context by the receiver.
    ik_sig_pub   : sender's 2624-byte hybrid public key
                   (ed25519_pub || ml_dsa87_pub) from their public bundle.
    expected_pub : optional locally pinned public key for TOFU enforcement.
                   Compared in constant time against ik_sig_pub before
                   signature verification. A mismatch raises
                   SignatureVerificationError with the same message as a bad
                   signature — this prevents oracle attacks distinguishing
                   "wrong key" from "bad signature".

    Raises
    ------
    SignatureVerificationError : verification failed for any reason
    MalformedSignedCiphertextError : ik_sig_pub is the wrong length
    """
    # ── TOFU pinning check ────────────────────────────────────────────────────
    if expected_pub is not None:
        # Constant-time comparison — hmac.compare_digest prevents timing oracle
        if not hmac.compare_digest(expected_pub, ik_sig_pub):
            raise SignatureVerificationError(
                "Signature verification failed."
            )

    # ── Validate public key length ────────────────────────────────────────────
    if len(ik_sig_pub) != HYBRID_PUBLIC_KEY_LEN:
        raise MalformedSignedCiphertextError(
            f"ik_sig_pub must be {HYBRID_PUBLIC_KEY_LEN} bytes "
            f"(ed25519_pub || ml_dsa87_pub), got {len(ik_sig_pub)}."
        )

    ed_pub_bytes  = ik_sig_pub[:ED25519_PUBLIC_KEY_LEN]
    dsa_pub_bytes = ik_sig_pub[ED25519_PUBLIC_KEY_LEN:]

    ed_sig  = signed.signature[:ED25519_SIGNATURE_LEN]
    dsa_sig = signed.signature[ED25519_SIGNATURE_LEN:]

    # ── Reconstruct sig_input ─────────────────────────────────────────────────
    sig_input = build_sig_input(
        ciphertext    = signed.ciphertext,
        aad           = aad,
        sender_id     = signed.sender_id,
        recipient_id  = signed.recipient_id,
        message_index = signed.message_index,
    )

    # ── Ed25519 verification ──────────────────────────────────────────────────
    try:
        ed_pub = Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
        ed_pub.verify(ed_sig, sig_input)
    except Exception:
        raise SignatureVerificationError("Signature verification failed.")

    # ── ML-DSA-87 verification ────────────────────────────────────────────────
    try:
        with oqs.Signature(SIG_ALG) as verifier:
            valid = verifier.verify(sig_input, dsa_sig, dsa_pub_bytes)
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
    Parse wire bytes, verify the hybrid signature, and return the
    SignedCiphertext. Convenience wrapper for the common receive path.

    Call order enforced internally:
      1. from_bytes() — parse and validate structure
      2. verify_ciphertext() — verify both signatures
      3. return SignedCiphertext for the caller to pass to aead.decrypt()

    Raises
    ------
    MalformedSignedCiphertextError : payload cannot be parsed
    SignatureVerificationError     : signature verification failed
    """
    signed = SignedCiphertext.from_bytes(data)
    verify_ciphertext(
        signed       = signed,
        aad          = aad,
        ik_sig_pub   = ik_sig_pub,
        expected_pub = expected_pub,
    )
    return signed
