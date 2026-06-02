"""
core/password.py

Argon2id password hashing and local key derivation.

Extracted from kdf.py — HKDF functions remain there.

Two distinct use cases, both using Argon2id but with different purposes:

  argon2id_hash() / argon2id_verify()
    Server-side password verification. Produces an encoded hash string
    stored in the database. The hash includes the salt and parameters so
    verification needs only the stored string and the plaintext password.

  argon2id_derive_key()
    Local key derivation. Derives a raw 32-byte key from a passphrase for
    encrypting the user's private key bundle at rest. Uses a separately
    stored local salt — cryptographically independent from the server-side
    hash even if the same passphrase is used for both.

WHY SEPARATE FROM SERVER-SIDE HASHING
    A server database breach exposes the server-side Argon2id hash but NOT
    the local key encryption key, because:
      - The salts are different (server salt is embedded in the hash string;
        local salt is stored alongside the encrypted key bundle on-device).
      - The derivation paths use different info strings in the HKDF step
        that follows (INFO_LOCAL_KEY_ENC vs the server hash has no HKDF step).

Parameters follow the OWASP Password Storage Cheat Sheet recommendation:
    time_cost   = 3        iterations
    memory_cost = 65536    KiB (64 MB)
    parallelism = 4        threads
    hash_len    = 32       bytes

References:
    RFC 9106  Argon2:        https://www.rfc-editor.org/rfc/rfc9106
    OWASP Password Storage:  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
"""

from __future__ import annotations

import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from argon2.low_level import hash_secret_raw, Type

from .constants import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
    ARGON2_SALT_LEN,
)


# Pre-configured PasswordHasher for server-side password verification.
# Parameters are defined in constants.py and justified there against OWASP.
_password_hasher = PasswordHasher(
    time_cost    = ARGON2_TIME_COST,
    memory_cost  = ARGON2_MEMORY_COST,
    parallelism  = ARGON2_PARALLELISM,
    hash_len     = ARGON2_HASH_LEN,
    salt_len     = ARGON2_SALT_LEN,
)


# ── Server-side password hashing ─────────────────────────────────────────────

def argon2id_hash(password: str) -> str:
    """
    Hash a password for server-side storage using Argon2id.

    Returns an encoded hash string that includes the salt, parameters, and
    hash — everything needed for future verification. Store this string
    directly in the database. Never store the password itself.

    Parameters
    ----------
    password : plaintext password string (Unicode)

    Returns
    -------
    str : Argon2id encoded hash string, e.g.:
          "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"
    """
    return _password_hasher.hash(password)


def argon2id_verify(stored_hash: str, password: str) -> bool:
    """
    Verify a password against a stored Argon2id hash.

    Returns True if the password matches, False otherwise.
    Never raises on a mismatch — always returns bool so callers don't
    need to catch exceptions for normal authentication failures.

    Parameters
    ----------
    stored_hash : the encoded hash string returned by argon2id_hash()
    password    : the plaintext password to verify

    Notes
    -----
    InvalidHashError (raised by _password_hasher.verify when stored_hash is
    malformed or not a valid Argon2 encoded string) is also caught and returns
    False. A corrupted stored_hash is treated as an authentication failure
    rather than a server error, to avoid leaking information about the hash
    format via exception propagation. Callers that need to distinguish a
    corrupted hash from a genuine mismatch should validate stored_hash before
    calling this function.
    """
    try:
        return _password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ── Local key derivation ──────────────────────────────────────────────────────

def argon2id_derive_key(
    passphrase: str,
    salt:       bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Derive a 32-byte key from a passphrase using Argon2id.

    Use this for local key encryption — NOT for server-side password storage.
    For server-side storage, use argon2id_hash() / argon2id_verify() instead.

    The returned key should be fed into hkdf_derive() with INFO_LOCAL_KEY_ENC
    before use, to provide an additional domain separation layer:

        from core.kdf import hkdf_derive, INFO_LOCAL_KEY_ENC
        raw_key, salt = argon2id_derive_key(passphrase)
        enc_key = hkdf_derive(raw_key, salt, INFO_LOCAL_KEY_ENC)

    Parameters
    ----------
    passphrase : the user's local passphrase (may differ from server password)
    salt       : 16-byte random salt. Generated freshly if not provided.
                 Store the returned salt alongside the encrypted key bundle.

    Returns
    -------
    (key: bytes, salt: bytes)
        key  : 32-byte derived key
        salt : the salt used (generated or as provided)

    Raises
    ------
    ValueError : if salt is provided but is not ARGON2_SALT_LEN bytes
    """
    if salt is None:
        salt = os.urandom(ARGON2_SALT_LEN)

    if len(salt) != ARGON2_SALT_LEN:
        raise ValueError(
            f"salt must be {ARGON2_SALT_LEN} bytes, got {len(salt)}"
        )

    key = hash_secret_raw(
        secret      = passphrase.encode("utf-8"),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEMORY_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = ARGON2_HASH_LEN,
        type        = Type.ID,
    )
    return key, salt
