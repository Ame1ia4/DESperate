"""
core/aead.py

ChaCha20-Poly1305 AEAD (RFC 8439).

Two encryption layers are provided:

  encrypt() / decrypt()
    Message payload encryption. Each message gets a unique single-use key
    from the Double Ratchet symmetric ratchet — nonce is derived from the
    key itself via HKDF, so no stateful counter is needed. Nonce uniqueness
    is guaranteed structurally by the key schedule: a fresh key is derived
    per message and deleted after use, making (key, nonce) reuse impossible
    without also reusing the key, which the ratchet prevents.

  encrypt_header() / decrypt_header()
    Message header encryption. The same header key is reused across all
    messages in a DH ratchet epoch, so nonce uniqueness requires a stateful
    monotonic counter (HeaderCounter). The counter is incremented and
    persisted atomically before every encryption — if the process crashes
    after persisting but before sending, the counter value is skipped (safe)
    rather than reused (unsafe).

Wire format — message:  nonce(12) || ciphertext || tag(16)
Wire format — header:   nonce(12) || ciphertext || tag(16)

References:
  RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
  Signal Double Ratchet spec:    https://signal.org/docs/specifications/doubleratchet/
  MLS protocol draft-17 §9.3:   https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17
"""

from __future__ import annotations

import hmac
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


# ── Constants ────────────────────────────────────────────────────────────────

# Maximum number of skipped message keys to store per session.
# Matches Signal Double Ratchet spec §2.6 recommendation.
# Prevents unbounded memory growth under a DoS scenario where an attacker
# sends many ratchet-advancing messages without valid ciphertexts.
MAX_SKIP: int = 1_000

_KEY_LEN   = 32   # ChaCha20-Poly1305 key length (bytes)
_NONCE_LEN = 12   # ChaCha20-Poly1305 nonce length (bytes)
_TAG_LEN   = 16   # Poly1305 authentication tag length (bytes)

# Minimum valid ciphertext length: nonce + tag (empty plaintext)
_MIN_CT_LEN = _NONCE_LEN + _TAG_LEN


# ── Internal nonce derivation ────────────────────────────────────────────────

def _derive_nonce(message_key: bytes, message_index: int) -> bytes:
    """
    Derive a 12-byte nonce from the message key and message index.

    Because the Double Ratchet key schedule guarantees each message_key
    is unique per (chain_step, message_index), using the key itself as
    HKDF input material provides implicit domain separation across chains
    without needing an explicit chain_index parameter.

    Nonce uniqueness guarantee:
      - Across chains: different chain steps produce different message keys,
        which produce different nonces even at the same message_index.
      - Within a chain: different message_index values produce different
        HKDF outputs under the same key.
      - Against state-loss replay: ratchet state is persisted atomically
        before any message key is returned to the caller, so crash recovery
        cannot re-derive a previously used key. This is the same guarantee
        the MLS reuse guard (§9.3) provides, achieved via the persistence
        layer instead. The guard is therefore not needed here.

    Reference: Signal DR spec §2.3 — nonce derived from message key.

    Parameters
    ----------
    message_key   : _KEY_LEN-byte message key from the symmetric ratchet
    message_index : position of this message in the sending chain (uint64)
    """
    if len(message_key) != _KEY_LEN:
        raise ValueError(
            f"message_key must be {_KEY_LEN} bytes, got {len(message_key)}"
        )
    if not (0 <= message_index < 2**64):
        raise ValueError("message_index must be a uint64")

    index_bytes = struct.pack("<Q", message_index)   # 8 bytes, little-endian

    return HKDF(
        algorithm = hashes.SHA256(),
        length    = _NONCE_LEN,
        salt      = index_bytes,
        info      = b"chacha20-poly1305-nonce-v1",
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

    Nonce is derived internally from message_key and message_index —
    the caller never supplies a nonce directly, eliminating the unsafe
    API surface where a caller could accidentally reuse one.

    Wire format:
      nonce (12) || ciphertext || tag (16)

    Parameters
    ----------
    message_key     : _KEY_LEN-byte single-use key from the Double Ratchet
                      symmetric ratchet. Must never be reused.
    plaintext       : message payload bytes
    associated_data : bound context (e.g. sender_id || recipient_id ||
                      session_id). Authenticated but not encrypted.
    message_index   : position of this message in the sending chain.
                      Used in nonce derivation — must match on decrypt.
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
    message_key     : _KEY_LEN-byte single-use key from the Double Ratchet
    data            : full wire bytes (nonce || ciphertext || tag)
    associated_data : must match what was passed to encrypt() exactly
    message_index   : must match what was passed to encrypt() exactly
    """
    if len(data) < _MIN_CT_LEN:
        raise ValueError(
            f"Ciphertext too short: need at least {_MIN_CT_LEN} bytes, "
            f"got {len(data)}"
        )

    wire_nonce     = data[:_NONCE_LEN]
    ct             = data[_NONCE_LEN:]

    # Reconstruct and verify the nonce in constant time before decrypting.
    # hmac.compare_digest is used rather than a hand-rolled loop — it is
    # guaranteed constant-time by the CPython implementation and is the
    # stdlib-recommended tool for timing-safe comparison (Python docs §hmac).
    # A mismatch means the wrong message_index was supplied or the nonce
    # was tampered with — treat identically to an AEAD tag failure.
    expected_nonce = _derive_nonce(message_key, message_index)
    if not hmac.compare_digest(wire_nonce, expected_nonce):
        raise InvalidTag()

    return ChaCha20Poly1305(message_key).decrypt(expected_nonce, ct, associated_data)


# ── Header encryption ────────────────────────────────────────────────────────
#
# Message headers contain ratchet public keys and message indices. The header
# key is reused across every message in a DH ratchet epoch — unlike message
# keys which rotate every message — so nonce uniqueness must be enforced by
# a stateful monotonic counter rather than derived from the key itself.
#
# The HeaderCounter (core/ratchet/header_counter.py) is owned by the ratchet
# session and passed in by the caller. It atomically persists the counter
# before returning a nonce, so no reuse guard is needed here either.

_HEADER_MIN_CT_LEN = _NONCE_LEN + _TAG_LEN


def encrypt_header(
    header_key:       bytes,
    header_plaintext: bytes,
    associated_data:  bytes,
    counter,                   # HeaderCounter — imported at session layer
) -> bytes:
    """
    Encrypt a message header under ChaCha20-Poly1305.

    Uses a stateful monotonic counter for nonce uniqueness — required
    because the same header_key is reused across multiple messages within
    a DH ratchet epoch, unlike message keys which are single-use.

    The counter is incremented and persisted atomically before encryption.
    If the persist fails, an OSError is raised and no encryption occurs —
    the caller must not attempt to send in this case.

    Wire format:
      nonce (12) || ciphertext || tag (16)

    Parameters
    ----------
    header_key       : _KEY_LEN-byte key for this DH ratchet epoch
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

    The nonce is read directly from the wire — the receiver does not need
    a counter because nonce authenticity is verified by the Poly1305 tag.
    If the nonce has been tampered with, decryption produces the wrong
    keystream and the tag fails.

    Parameters
    ----------
    header_key      : _KEY_LEN-byte key for this DH ratchet epoch
    data            : full wire bytes (nonce || ciphertext || tag)
    associated_data : must exactly match what was passed to encrypt_header()

    Raises
    ------
    ValueError  : if data is too short
    InvalidTag  : if authentication fails
    """
    if len(data) < _HEADER_MIN_CT_LEN:
        raise ValueError(
            f"Header ciphertext too short: "
            f"need at least {_HEADER_MIN_CT_LEN} bytes, got {len(data)}"
        )

    nonce = data[:_NONCE_LEN]
    ct    = data[_NONCE_LEN:]
    return ChaCha20Poly1305(header_key).decrypt(nonce, ct, associated_data)
