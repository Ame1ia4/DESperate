"""
core/aead.py

ChaCha20-Poly1305 AEAD (RFC 8439) with MLS-spec reuse guard.

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
  1. Base nonce derived via HKDF(key, message_index) — implicit domain
     separation across chains since every message key is unique.
  2. 4-byte random reuse_guard XORed into nonce[0:4] per MLS §9.3.

Nonce construction for header encryption:
  1. Nonce comes directly from HeaderCounter.next_nonce() — a uint64
     counter encoded as 12 bytes, strictly monotonically increasing.
  2. No reuse_guard needed: the counter is statefully persisted and never
     repeats within a session. Cross-session uniqueness is provided by
     independent header keys, not the counter value.

Wire format — message:  reuse_guard(4) || nonce(12) || ciphertext || tag(16)
Wire format — header:   nonce(12)      || ciphertext || tag(16)

References:
  RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
  Signal Double Ratchet spec:    https://signal.org/docs/specifications/doubleratchet/
  MLS protocol draft-17 §9.3:   https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17
"""

from __future__ import annotations

import os
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
MAX_SKIP: int = 1000

# Wire format offsets
_REUSE_GUARD_LEN = 4
_NONCE_LEN       = 12
_TAG_LEN         = 16
_HEADER_LEN      = _REUSE_GUARD_LEN + _NONCE_LEN  # 16 bytes before ciphertext


# ── Internal nonce derivation ────────────────────────────────────────────────

def _derive_base_nonce(message_key: bytes, message_index: int) -> bytes:
    """
    Derive a 12-byte base nonce from the message key and message index.

    Because the Double Ratchet key schedule guarantees each message_key
    is unique per (chain_step, message_index), using the key itself as
    HKDF input material provides implicit domain separation across chains
    without needing an explicit chain_index parameter.

    This removes the unsafe caller-supplied chain_index from the API
    (PR point 1) and grounds nonce derivation in the key schedule itself,
    consistent with Signal spec §2.3.

    Parameters
    ----------
    message_key   : 32-byte message key from the symmetric ratchet
    message_index : position of this message in the sending chain (uint64)
    """
    if len(message_key) != 32:
        raise ValueError(f"message_key must be 32 bytes, got {len(message_key)}")
    if not (0 <= message_index < 2**64):
        raise ValueError("message_index must be a uint64")

    index_bytes = struct.pack("<Q", message_index)   # 8 bytes, little-endian

    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length    = 12,
        salt      = index_bytes,
        info      = b"chacha20-poly1305-nonce-v1",
    )
    return hkdf.derive(message_key)


def _apply_reuse_guard(base_nonce: bytes, reuse_guard: bytes) -> bytes:
    """
    XOR a 4-byte reuse guard into the first 4 bytes of the base nonce.

    MLS draft-ietf-mls-protocol-17 §9.3:
      'the sender MUST generate a fresh random four-byte reuse_guard value
       and XOR it with the first four bytes of the nonce before use.'

    This protects against state-loss: if a client crashes and restores from
    a snapshot, the deterministic base nonce might repeat — the random guard
    ensures the final nonce is still unique with overwhelming probability.

    Parameters
    ----------
    base_nonce  : 12-byte deterministic nonce from _derive_base_nonce()
    reuse_guard : 4 bytes from os.urandom(4)
    """
    if len(base_nonce)  != 12: raise ValueError("base_nonce must be 12 bytes")
    if len(reuse_guard) != 4:  raise ValueError("reuse_guard must be 4 bytes")

    guarded = bytearray(base_nonce)
    for i in range(4):
        guarded[i] ^= reuse_guard[i]
    return bytes(guarded)


# ── Public API ───────────────────────────────────────────────────────────────

def encrypt(
    message_key:    bytes,
    plaintext:      bytes,
    associated_data: bytes,
    message_index:  int,
) -> bytes:
    """
    Encrypt plaintext with ChaCha20-Poly1305.

    Nonce is derived internally from message_key and message_index —
    the caller never supplies a nonce directly, eliminating the unsafe
    API surface identified in the PR review.

    Wire format:
      reuse_guard (4) || nonce (12) || ciphertext || tag (16)

    Parameters
    ----------
    message_key     : 32-byte single-use key from the Double Ratchet
                      symmetric ratchet. Must never be reused.
    plaintext       : message payload bytes
    associated_data : bound context (e.g. sender_id || recipient_id ||
                      session_id). Authenticated but not encrypted.
    message_index   : position of this message in the sending chain.
                      Used in nonce derivation; included in wire format
                      implicitly via the nonce.
    """
    base_nonce  = _derive_base_nonce(message_key, message_index)
    reuse_guard = os.urandom(_REUSE_GUARD_LEN)
    nonce       = _apply_reuse_guard(base_nonce, reuse_guard)

    ct = ChaCha20Poly1305(message_key).encrypt(nonce, plaintext, associated_data)

    # Wire: reuse_guard || nonce || ciphertext+tag
    return reuse_guard + nonce + ct


def decrypt(
    message_key:    bytes,
    data:           bytes,
    associated_data: bytes,
    message_index:  int,
) -> bytes:
    """
    Decrypt a ciphertext produced by encrypt().

    Recovers the reuse_guard from the wire format, reconstructs the
    expected base nonce, re-applies the guard, and verifies the tag.
    InvalidTag is raised if anything has been tampered with.

    Parameters
    ----------
    message_key     : 32-byte single-use key from the Double Ratchet
    data            : full wire bytes (reuse_guard || nonce || ct+tag)
    associated_data : must match what was passed to encrypt() exactly
    message_index   : must match what was passed to encrypt() exactly
    """
    if len(data) < _HEADER_LEN + _TAG_LEN:
        raise ValueError(
            f"Ciphertext too short: need at least {_HEADER_LEN + _TAG_LEN} bytes"
        )

    reuse_guard = data[:_REUSE_GUARD_LEN]
    nonce       = data[_REUSE_GUARD_LEN : _REUSE_GUARD_LEN + _NONCE_LEN]
    ct          = data[_HEADER_LEN:]

    # Verify the nonce is consistent with the message key and index.
    # This catches state-desync bugs where the wrong message_index is supplied.
    expected_base = _derive_base_nonce(message_key, message_index)
    expected_nonce = _apply_reuse_guard(expected_base, reuse_guard)
    if nonce != expected_nonce:
        raise InvalidTag()   # treat nonce mismatch same as tag failure

    return ChaCha20Poly1305(message_key).decrypt(nonce, ct, associated_data)


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

# Header wire format offsets
_HEADER_NONCE_LEN = 12   # full nonce from HeaderCounter (no reuse_guard needed)
_HEADER_TAG_LEN   = 16


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

    Note: no reuse_guard is prepended. The stateful counter already
    guarantees strict uniqueness within a session. The reuse_guard is
    only needed when a deterministic value might repeat after state loss —
    the counter's atomic persistence handles that directly.

    Parameters
    ----------
    header_key       : 32-byte key for this DH ratchet epoch
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
    header_key      : 32-byte key for this DH ratchet epoch
    data            : full wire bytes (nonce || ciphertext || tag)
    associated_data : must exactly match what was passed to encrypt_header()

    Raises
    ------
    ValueError  : if data is too short
    InvalidTag  : if authentication fails
    """
    min_len = _HEADER_NONCE_LEN + _HEADER_TAG_LEN
    if len(data) < min_len:
        raise ValueError(
            f"Header ciphertext too short: "
            f"need at least {min_len} bytes, got {len(data)}"
        )

    nonce = data[:_HEADER_NONCE_LEN]
    ct    = data[_HEADER_NONCE_LEN:]
    return ChaCha20Poly1305(header_key).decrypt(nonce, ct, associated_data)
