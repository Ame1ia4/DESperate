"""
core/signatures.py

ML-DSA-87 message signing and verification over ciphertext payloads.

DESIGN RATIONALE
----------------
Signal's Double Ratchet provides implicit sender authentication: if a message
decrypts successfully under a key derived from the shared ratchet state, it
must have come from someone who holds the same state (i.e. the other party).
That is sufficient against a passive adversary.

This module adds EXPLICIT ML-DSA-87 signatures over ciphertext for two
reasons specific to this deployment:

  1. Post-quantum authenticity — a quantum adversary breaking X25519 could
     impersonate senders by forging DH key agreement. ML-DSA-87 (FIPS 204
     level 5) provides authenticity that holds even if all classical
     primitives are broken.

  2. Server-compromise resistance — a fully compromised server can inject
     arbitrary ciphertexts into the message queue. A valid ML-DSA-87
     signature, verifiable against the sender's published identity key,
     means the server cannot forge messages from one user to another even
     with full database access.

WHAT IS SIGNED
--------------
The signature covers:

    sig_input = length-prefixed(ciphertext)
             || length-prefixed(associated_data)
             || length-prefixed(sender_id)
             || length-prefixed(recipient_id)
             || message_index (8 bytes, little-endian uint64)

Length-prefixed encoding (4-byte little-endian uint32 prefix per field)
prevents substitution attacks where an adversary rearranges valid fields
from different messages to construct a new signed input.

WHAT IS NOT SIGNED
------------------
The nonce is NOT separately signed. The nonce is derived deterministically
from the message key and message_index in aead.py (_derive_nonce), so it
is implicitly bound by signing message_index. Signing it separately would
be redundant.

The ML-DSA-87 signing key (SigningKeypair.secret_key) is the user's
long-term identity signing key, stored encrypted at rest in state_store.py.
It must never appear in a SignedCiphertext or be logged anywhere.

WIRE FORMAT
-----------
SignedCiphertext.to_bytes():

    ciphertext_len  (4 bytes, uint32 LE)
    ciphertext      (variable)
    signature_len   (4 bytes, uint32 LE)
    signature       (4627 bytes for ML-DSA-87)
    sender_pub_len  (4 bytes, uint32 LE)
    sender_pub      (2592 bytes for ML-DSA-87 public key)

Associated data, sender_id, recipient_id, and message_index are NOT
included in the wire format — they are provided by the caller at verify
time and must match exactly (same as AEAD associated_data semantics).

References:
    FIPS 204 (ML-DSA):    https://doi.org/10.6028/NIST.FIPS.204
    Signal DR spec §3.1:  https://signal.org/docs/specifications/doubleratchet/
    Signal PQXDH spec:    https://signal.org/docs/specifications/pqxdh/
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import oqs
from cryptography.exceptions import InvalidSignature

from .constants import SIG_ALG, DSA_SIGNATURE_LEN, DSA_PUBLIC_KEY_LEN
from .keys import SigningKeypair


# ── Constants ─────────────────────────────────────────────────────────────────

# Minimum wire length for a SignedCiphertext:
#   3 × 4-byte length prefix + 0-byte ciphertext + DSA_SIGNATURE_LEN + DSA_PUBLIC_KEY_LEN
_MIN_WIRE_LEN: int = 3 * 4 + DSA_SIGNATURE_LEN + DSA_PUBLIC_KEY_LEN


# ── Exceptions ────────────────────────────────────────────────────────────────

class SignatureVerificationError(Exception):
    """
    Raised when ML-DSA-87 signature verification fails.

    This indicates either:
      - the ciphertext was tampered with after signing, or
      - the signature was produced by a different key than expected, or
      - the wrong sender_id / recipient_id / message_index was supplied.

    In all cases the message must be discarded — do not attempt decryption.
    """


class MalformedSignedCiphertextError(Exception):
    """
    Raised when a SignedCiphertext wire encoding is structurally invalid.
    Distinct from SignatureVerificationError — the bytes are not a valid
    encoding at all, not merely a valid encoding with a bad signature.
    """


# ── Signing input construction ────────────────────────────────────────────────

def _encode_field(data: bytes) -> bytes:
    """
    Length-prefix a field with a 4-byte little-endian uint32.

    This encoding prevents substitution attacks: two fields of different
    lengths but the same concatenated bytes cannot produce the same
    encoded output.
    """
    if len(data) > 0xFFFFFFFF:
        raise ValueError(f"field too large to encode: {len(data)} bytes")
    return struct.pack("<I", len(data)) + data


def build_sig_input(
    ciphertext:      bytes,
    associated_data: bytes,
    sender_id:       str,
    recipient_id:    str,
    message_index:   int,
) -> bytes:
    """
    Construct the canonical byte string over which ML-DSA-87 signs.

    All five fields are bound into the input so that a valid signature
    is tied to this specific (ciphertext, context) combination. Changing
    any field — including sender/recipient identity or message position —
    invalidates the signature.

    Parameters
    ----------
    ciphertext      : the AEAD ciphertext output from aead.encrypt()
                      (wire format: nonce || ct || tag)
    associated_data : the associated data passed to aead.encrypt()
    sender_id       : the sender's device or user ID string
    recipient_id    : the recipient's device or user ID string
    message_index   : position in the sending chain (must match aead.encrypt)

    Returns
    -------
    bytes : the canonical input to pass to ML-DSA-87 sign / verify
    """
    if not (0 <= message_index < 2**64):
        raise ValueError("message_index must be a uint64")

    return (
        _encode_field(ciphertext)
        + _encode_field(associated_data)
        + _encode_field(sender_id.encode("utf-8"))
        + _encode_field(recipient_id.encode("utf-8"))
        + struct.pack("<Q", message_index)   # 8 bytes, little-endian uint64
    )


# ── SignedCiphertext ──────────────────────────────────────────────────────────

@dataclass
class SignedCiphertext:
    """
    An AEAD ciphertext together with its ML-DSA-87 signature and the
    sender's signing public key.

    The public key is included so the recipient can verify without a
    separate lookup, and so the server cannot substitute a different key.
    The recipient must independently verify the public key against their
    locally pinned copy (TOFU) before trusting the signature.

    Fields
    ------
    ciphertext  : aead.encrypt() output (nonce || ct || tag)
    signature   : ML-DSA-87 signature over build_sig_input(...) output
    sender_pub  : sender's ML-DSA-87 identity public key (2592 bytes)
    """

    ciphertext: bytes
    signature:  bytes
    sender_pub: bytes

    def __post_init__(self) -> None:
        if len(self.signature) != DSA_SIGNATURE_LEN:
            raise ValueError(
                f"signature must be {DSA_SIGNATURE_LEN} bytes, "
                f"got {len(self.signature)}"
            )
        if len(self.sender_pub) != DSA_PUBLIC_KEY_LEN:
            raise ValueError(
                f"sender_pub must be {DSA_PUBLIC_KEY_LEN} bytes, "
                f"got {len(self.sender_pub)}"
            )

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        """
        Serialise to wire format:

            ciphertext_len (4, uint32 LE) || ciphertext
            signature_len  (4, uint32 LE) || signature
            sender_pub_len (4, uint32 LE) || sender_pub
        """
        return (
            _encode_field(self.ciphertext)
            + _encode_field(self.signature)
            + _encode_field(self.sender_pub)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedCiphertext:
        """
        Deserialise from wire format produced by to_bytes().

        Raises
        ------
        MalformedSignedCiphertextError : if data is too short or lengths
                                         are inconsistent
        """
        if len(data) < _MIN_WIRE_LEN:
            raise MalformedSignedCiphertextError(
                f"wire data too short: need at least {_MIN_WIRE_LEN} bytes, "
                f"got {len(data)}"
            )

        offset = 0

        def _read_field(name: str) -> bytes:
            nonlocal offset
            if offset + 4 > len(data):
                raise MalformedSignedCiphertextError(
                    f"truncated length prefix for field '{name}'"
                )
            (length,) = struct.unpack_from("<I", data, offset)
            offset += 4
            if offset + length > len(data):
                raise MalformedSignedCiphertextError(
                    f"field '{name}' claims {length} bytes "
                    f"but only {len(data) - offset} remain"
                )
            value   = data[offset : offset + length]
            offset += length
            return value

        try:
            ciphertext = _read_field("ciphertext")
            signature  = _read_field("signature")
            sender_pub = _read_field("sender_pub")
        except MalformedSignedCiphertextError:
            raise
        except Exception as exc:
            raise MalformedSignedCiphertextError(
                f"unexpected error deserialising SignedCiphertext: {exc}"
            ) from exc

        return cls(
            ciphertext = ciphertext,
            signature  = signature,
            sender_pub = sender_pub,
        )

    def __repr__(self) -> str:
        return (
            f"SignedCiphertext("
            f"ciphertext={len(self.ciphertext)}B, "
            f"signature={self.signature.hex()[:16]}…, "
            f"sender_pub={self.sender_pub.hex()[:16]}…)"
        )


# ── Sign ──────────────────────────────────────────────────────────────────────

def sign_ciphertext(
    ciphertext:      bytes,
    associated_data: bytes,
    sender_id:       str,
    recipient_id:    str,
    message_index:   int,
    signing_keypair: SigningKeypair,
) -> SignedCiphertext:
    """
    Sign an AEAD ciphertext with the sender's ML-DSA-87 identity key.

    Call this AFTER aead.encrypt() — the signature covers the ciphertext,
    not the plaintext. Never sign plaintext.

    Parameters
    ----------
    ciphertext      : output of aead.encrypt() — nonce || ct || tag
    associated_data : the same associated_data passed to aead.encrypt()
    sender_id       : the sender's device or user ID string
    recipient_id    : the recipient's device or user ID string
    message_index   : the message_index passed to aead.encrypt()
    signing_keypair : sender's ML-DSA-87 identity SigningKeypair (from keys.py)

    Returns
    -------
    SignedCiphertext : ciphertext + signature + sender's public key

    Example
    -------
    # After encrypting:
    ct = aead.encrypt(msg_key, plaintext, aad, message_index)

    # Sign:
    signed = sign_ciphertext(
        ciphertext      = ct,
        associated_data = aad,
        sender_id       = my_device_id,
        recipient_id    = their_device_id,
        message_index   = message_index,
        signing_keypair = my_identity_bundle.ik_sig,
    )

    # Send signed.to_bytes() on the wire.
    """
    if not ciphertext:
        raise ValueError("ciphertext must not be empty")

    sig_input = build_sig_input(
        ciphertext      = ciphertext,
        associated_data = associated_data,
        sender_id       = sender_id,
        recipient_id    = recipient_id,
        message_index   = message_index,
    )

    signature = signing_keypair.sign(sig_input)

    return SignedCiphertext(
        ciphertext = ciphertext,
        signature  = signature,
        sender_pub = signing_keypair.public_key,
    )


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_ciphertext(
    signed:          SignedCiphertext,
    associated_data: bytes,
    sender_id:       str,
    recipient_id:    str,
    message_index:   int,
    expected_pub:    bytes | None = None,
) -> None:
    """
    Verify the ML-DSA-87 signature on a SignedCiphertext.

    Must be called BEFORE aead.decrypt(). If this raises, the message
    must be discarded without attempting decryption.

    Parameters
    ----------
    signed          : the SignedCiphertext received from the wire
    associated_data : the associated_data expected for this message
                      (must match what was passed to sign_ciphertext)
    sender_id       : the expected sender's device or user ID
    recipient_id    : the expected recipient's device or user ID
    message_index   : the expected position in the chain
    expected_pub    : optional locally-pinned ML-DSA-87 public key for the
                      sender. If provided, the key in the SignedCiphertext
                      is checked against it (constant-time). If they differ,
                      SignatureVerificationError is raised before attempting
                      signature verification — prevents key substitution by
                      a compromised server.
                      If None, the key in the SignedCiphertext is used
                      directly (TOFU — first message from this sender).

    Raises
    ------
    SignatureVerificationError  : signature invalid, key mismatch, or
                                  any other authentication failure.
                                  Always discard the message on this exception.
    MalformedSignedCiphertextError : structural issue in signed (propagated)

    Returns
    -------
    None — returns normally only if the signature is valid.
    """
    # ── Key pinning check ─────────────────────────────────────────────────────
    # Constant-time comparison — prevents timing oracle on key mismatch.
    if expected_pub is not None:
        import hmac as _hmac
        if not _hmac.compare_digest(signed.sender_pub, expected_pub):
            raise SignatureVerificationError(
                "sender public key in message does not match locally pinned key. "
                "Possible server key substitution attack. Message discarded."
            )

    # ── Reconstruct signing input ─────────────────────────────────────────────
    sig_input = build_sig_input(
        ciphertext      = signed.ciphertext,
        associated_data = associated_data,
        sender_id       = sender_id,
        recipient_id    = recipient_id,
        message_index   = message_index,
    )

    # ── ML-DSA-87 verification ────────────────────────────────────────────────
    # Use a uniform error message regardless of failure mode — prevents
    # an oracle distinguishing key mismatch from signature forgery.
    try:
        with oqs.Signature(SIG_ALG) as verifier:
            valid = verifier.verify(sig_input, signed.signature, signed.sender_pub)
    except Exception as exc:
        raise SignatureVerificationError(
            "signature verification failed"
        ) from exc

    if not valid:
        raise SignatureVerificationError(
            "signature verification failed"
        )


# ── Verify and extract ────────────────────────────────────────────────────────

def verify_and_extract(
    wire_bytes:      bytes,
    associated_data: bytes,
    sender_id:       str,
    recipient_id:    str,
    message_index:   int,
    expected_pub:    bytes | None = None,
) -> bytes:
    """
    Convenience function: deserialise, verify, and return the ciphertext.

    Combines from_bytes() + verify_ciphertext() into a single call for the
    common receive path. Returns the raw ciphertext ready to pass to
    aead.decrypt() — only if the signature is valid.

    Parameters
    ----------
    wire_bytes      : SignedCiphertext.to_bytes() output received from server
    associated_data : expected associated data for this message
    sender_id       : expected sender ID
    recipient_id    : expected recipient ID
    message_index   : expected message index
    expected_pub    : locally pinned sender public key (or None for TOFU)

    Returns
    -------
    bytes : the AEAD ciphertext (nonce || ct || tag), ready for aead.decrypt()

    Raises
    ------
    MalformedSignedCiphertextError : if wire_bytes cannot be parsed
    SignatureVerificationError      : if the signature does not verify

    Example
    -------
    # Receive path:
    ct = verify_and_extract(
        wire_bytes      = received_bytes,
        associated_data = aad,
        sender_id       = their_device_id,
        recipient_id    = my_device_id,
        message_index   = expected_index,
        expected_pub    = pinned_sender_pub,   # from TOFU store
    )
    plaintext = aead.decrypt(msg_key, ct, aad, expected_index)
    """
    signed = SignedCiphertext.from_bytes(wire_bytes)
    verify_ciphertext(
        signed          = signed,
        associated_data = associated_data,
        sender_id       = sender_id,
        recipient_id    = recipient_id,
        message_index   = message_index,
        expected_pub    = expected_pub,
    )
    return signed.ciphertext
