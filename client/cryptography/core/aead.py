"""
core/aead.py

ChaCha20-Poly1305 AEAD (RFC 8439).

Two encryption layers:
  encrypt() / decrypt()               — message payload, nonce derived from key via HKDF
  encrypt_header() / decrypt_header() — header, nonce from stateful HeaderCounter

Wire format — message:  nonce(12) || ciphertext || tag(16)
Wire format — header:   nonce(12) || ciphertext || tag(16)
"""

from __future__ import annotations

import hmac
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from .constants import KEY_LEN, NONCE_LEN, TAG_LEN, MIN_CT_LEN, MAX_SKIP, NONCE_INFO


# ── Internal nonce derivation ────────────────────────────────────────────────

def _derive_nonce(message_key: bytes, message_index: int) -> bytes:
    """
    Derive a 12-byte nonce from the message key and message index.

    Parameters
    ----------
    message_key   : KEY_LEN-byte message key from the symmetric ratchet
    message_index : position of this message in the sending chain (uint64)
    """
    if len(message_key) != KEY_LEN:
        raise ValueError(
            f"message_key must be {KEY_LEN} bytes, got {len(message_key)}"
        )
    if not (0 <= message_index < 2**64):
        raise ValueError("message_index must be a uint64")

    index_bytes = struct.pack("<Q", message_index)   # 8 bytes, little-endian

    return HKDF(
        algorithm = hashes.SHA256(),
        length    = NONCE_LEN,
        salt      = index_bytes,
        info      = NONCE_INFO,
    ).derive(message_key)


# ── Message encryption ────────────────────────────────────────────────────────

def encrypt(
    message_key:     bytes,
    plaintext:       bytes,
    associated_data: bytes,
    message_index:   int,
) -> bytes:
    """
    Encrypt plaintext with ChaCha20-Poly1305.

    Wire format: nonce (12) || ciphertext || tag (16)

    Parameters
    ----------
    message_key     : KEY_LEN-byte single-use key from the Double Ratchet.
                      Must never be reused.
    plaintext       : message payload bytes
    associated_data : bound context (e.g. sender_id || recipient_id ||
                      session_id). Authenticated but not encrypted.
    message_index   : position in the sending chain; used in nonce
                      derivation — must match on decrypt.
    """
    nonce = _derive_nonce(message_key, message_index)
    ct    = ChaCha20Poly1305(message_key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def decrypt(
    message_key:     bytes,
    data:            bytes,
    associated_data: bytes,
    message_index:   int,
) -> bytes:
    """
    Decrypt a ciphertext produced by encrypt().

    Reconstructs the expected nonce from message_key and message_index,
    verifies it against the wire using hmac.compare_digest (constant-time),
    then delegates authentication and decryption to ChaCha20-Poly1305.
    InvalidTag is raised if anything has been tampered with.

    Parameters
    ----------
    message_key     : KEY_LEN-byte single-use key from the Double Ratchet
    data            : full wire bytes (nonce || ciphertext || tag)
    associated_data : must match what was passed to encrypt() exactly
    message_index   : must match what was passed to encrypt() exactly
    """
    if len(data) < MIN_CT_LEN:
        raise ValueError(
            f"Ciphertext too short: need at least {MIN_CT_LEN} bytes, "
            f"got {len(data)}"
        )

    wire_nonce     = data[:NONCE_LEN]
    ct             = data[NONCE_LEN:]

    expected_nonce = _derive_nonce(message_key, message_index)
    if not hmac.compare_digest(wire_nonce, expected_nonce):
        raise InvalidTag()

    return ChaCha20Poly1305(message_key).decrypt(expected_nonce, ct, associated_data)


# ── Header encryption ────────────────────────────────────────────────────────

def encrypt_header(
    header_key:       bytes,
    header_plaintext: bytes,
    associated_data:  bytes,
    counter,                   # HeaderCounter — imported at session layer
) -> bytes:
    """
    Encrypt a message header under ChaCha20-Poly1305.

    The counter is incremented and persisted atomically before encryption.
    If the persist fails, an OSError is raised and no encryption occurs.

    Wire format: nonce (12) || ciphertext || tag (16)

    Parameters
    ----------
    header_key       : KEY_LEN-byte key for this DH ratchet epoch
    header_plaintext : serialised header bytes (ratchet pub key, indices)
    associated_data  : bound context, e.g. session_id. Must match decrypt.
    counter          : HeaderCounter for this session — advanced in place
    """
    nonce = counter.next_nonce()   # atomic persist happens inside here
    ct    = ChaCha20Poly1305(header_key).encrypt(nonce, header_plaintext, associated_data)
    return nonce + ct


def decrypt_header(
    header_key:      bytes,
    data:            bytes,
    associated_data: bytes,
) -> bytes:
    """
    Decrypt a header ciphertext produced by encrypt_header().

    Parameters
    ----------
    header_key      : KEY_LEN-byte key for this DH ratchet epoch
    data            : full wire bytes (nonce || ciphertext || tag)
    associated_data : must exactly match what was passed to encrypt_header()

    Raises
    ------
    ValueError  : if data is too short
    InvalidTag  : if authentication fails
    """
    if len(data) < MIN_CT_LEN:
        raise ValueError(
            f"Header ciphertext too short: "
            f"need at least {MIN_CT_LEN} bytes, got {len(data)}"
        )

    nonce = data[:NONCE_LEN]
    ct    = data[NONCE_LEN:]
    return ChaCha20Poly1305(header_key).decrypt(nonce, ct, associated_data)
