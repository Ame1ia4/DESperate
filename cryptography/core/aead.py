"""
core/aead.py

ChaCha20-Poly1305 AEAD (RFC 8439).

Two encryption layers are provided:

  encrypt() / decrypt()
    Message payload encryption. Each message gets a unique single-use key
    from the Double Ratchet symmetric ratchet — nonce is derived from the
    key itself, so no stateful counter is needed.

  encrypt_header() / decrypt_header()
    Message header encryption. The same header key is reused across all
    messages in a DH ratchet epoch, so nonce uniqueness requires a
    stateful monotonic counter (HeaderCounter). The counter is advanced
    and persisted atomically before every encryption.

Nonce construction for message encryption:
  Base nonce derived via HKDF(key=message_key, salt=message_index) — nonce
  uniqueness is guaranteed by the Double Ratchet key schedule, which produces
  a unique message key per message. The reuse guard (MLS §9.3) is omitted
  because ratchet state is persisted atomically before any message key is
  used — crash recovery cannot re-derive a previously used key. This matches
  Signal's own implementation.

Nonce construction for header encryption:
  Nonce comes directly from HeaderCounter.next_nonce() — a uint64 counter
  encoded as 12 bytes, strictly monotonically increasing, persisted atomically
  before every use. No reuse guard needed: atomic persistence provides the
  same guarantee directly. Cross-session uniqueness is provided by independent
  header keys derived per session, not by the counter value alone.

Wire format — message:  nonce(12) || ciphertext || tag(16)
Wire format — header:   nonce(12) || ciphertext || tag(16)

References:
  RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
  Signal Double Ratchet spec:    https://signal.org/docs/specifications/doubleratchet/
  MLS protocol draft-17 §9.3:   https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17
"""

from __future__ import annotations

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

_KEY_LEN  = 32   # ChaCha20-Poly1305 key length (bytes)
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

    The reuse guard (MLS §9.3) is intentionally omitted. Ratchet state
    is persisted atomically before any message key is returned to the
    caller — crash recovery cannot re-derive a used key, so the guard's
    protection against state-loss replay is provided by the persistence
    layer rather than by randomness. Omitting the guard simplifies the
    wire format (saving 4 bytes per message) and removes a source of
    non-determinism that would complicate testing.

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
    API surface identified in the PR review.

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

    Reconstructs the nonce from message_key and message_index, then
    delegates authentication and decryption to ChaCha20-Poly1305.
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

    # Reconstruct and verify the nonce before decrypting.
    # A mismatch means the wrong message_index was supplied or the nonce
    # was tampered with — treat identically to a tag failure.
    expected_nonce = _derive_nonce(message_key, message_index)
    if not _constant_time_equal(wire_nonce, expected_nonce):
        raise InvalidTag()

    return ChaCha20Poly1305(message_key).decrypt(expected_nonce, ct, associated_data)


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    Prevents timing side-channels on nonce verification.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ── Header encryption ────────────────────────────────────────────────────────
#
# Headers contain ratchet public keys and message indices. Unlike message
# keys, the header key is reused across every message in a DH ratchet epoch,
# so nonce uniqueness cannot be derived from the key alone — it requires a
# stateful counter.
#
# The HeaderCounter is owned by the ratchet session, not by this module.
# aead.py calls counter.next_nonce() which:
#   1. Increments the counter
#   2. Persists it atomically to disk
#   3. Returns the nonce bytes
# This happens before encryption — if the process crashes after persist
# but before sending, the counter value is skipped (safe) not reused (unsafe).

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
    a DH ratchet epoch (unlike message keys which are single-use).

    The counter is advanced and persisted atomically before encryption.
    If the persist fails, an OSError is raised and no encryption occurs.

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
    a counter because nonce verification is handled by the Poly1305 tag.
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
