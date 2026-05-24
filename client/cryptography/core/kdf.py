"""
core/kdf.py

Key derivation functions for the PQXDH + Double Ratchet stack.

Two primitives are provided:

  hkdf_derive()
    HKDF-SHA256 (RFC 5869) for deriving keying material from shared secrets.
    Used in PQXDH session initiation, the Double Ratchet root KDF, and local
    key encryption. Each usage site has a distinct, hardcoded info string
    (domain separation) so that keys derived for one purpose cannot be
    confused with keys derived for another, even if the input material is
    the same.

  argon2id_hash() / argon2id_verify()
    Argon2id (RFC 9106) for password hashing and local key derivation.
    Parameters follow the OWASP Password Storage Cheat Sheet recommendation:
      time_cost   = 3   iterations
      memory_cost = 65536 KiB (64 MB)
      parallelism = 4   threads
      hash_len    = 32  bytes
    These parameters are justified against OWASP and must be cited in the
    design document.

Domain separation — why it matters:
    Without distinct info strings, two HKDF calls with the same IKM and salt
    could produce the same output key for different purposes. For example, if
    the PQXDH shared secret and the local key encryption key were both derived
    with an empty info string, a server that learns one context could
    potentially attack the other. Hardcoded info strings make each derivation
    context cryptographically independent.

    Info strings follow the format: "<protocol>-<version>-<purpose>"
    They are defined as module-level constants so every usage site is
    auditable in one place.

References:
    RFC 5869  HKDF:          https://www.rfc-editor.org/rfc/rfc5869
    RFC 9106  Argon2:        https://www.rfc-editor.org/rfc/rfc9106
    OWASP Password Storage:  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    Signal PQXDH spec:       https://signal.org/docs/specifications/pqxdh/
    Signal DR spec §3.1:     https://signal.org/docs/specifications/doubleratchet/
"""

from __future__ import annotations

import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from argon2.low_level import hash_secret_raw, Type

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ── HKDF domain separation info strings ─────────────────────────────────────
#
# Every info string is hardcoded here and nowhere else. Adding a new usage
# site means adding a new constant — never passing an ad-hoc string to
# hkdf_derive() directly. This makes the full set of derivation contexts
# auditable at a glance.
#
# Versioned ("v1") so future protocol changes can introduce new strings
# without ambiguity.

# PQXDH session initiation — derives the initial shared secret SK from the
# combined classical + PQ DH outputs. See PQXDH spec §3.3.
INFO_PQXDH_SK           = b"pqxdh-v1-shared-secret"

# Double Ratchet root KDF — derives new root key and chain key from the
# current root key and a DH/KEM output. Signal DR spec §3.1 KDF_RK.
INFO_ROOT_KDF           = b"dr-v1-root-kdf"

# Double Ratchet chain KDF — derives message key and next chain key from
# the current chain key. Signal DR spec §3.1 KDF_CK.
INFO_CHAIN_KDF          = b"dr-v1-chain-kdf"

# Header key derivation — derives sending and receiving header keys as
# additional output from the root KDF during a DH ratchet step.
# Signal DR spec §4.2.
INFO_HEADER_KEY         = b"dr-v1-header-key"

# Local private key encryption — derives the key used to encrypt the user's
# long-term private key bundle at rest. Separate from server-side password
# hashing so the two derivation paths are cryptographically independent.
INFO_LOCAL_KEY_ENC      = b"local-v1-key-encryption"

# Local key derivation master — derives a master key from the user's
# passphrase via Argon2id before feeding into HKDF for local key encryption.
# The salt used here is stored locally and is separate from the server-side
# password hash salt.
INFO_LOCAL_KEY_MASTER   = b"local-v1-master-key"


# ── Argon2id parameters ──────────────────────────────────────────────────────
#
# OWASP Password Storage Cheat Sheet recommendation (as of 2024):
#   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
#
# These are the minimum recommended values. Do not reduce them.
# Increasing memory_cost or time_cost improves security at the cost of
# latency — acceptable for a login flow, potentially not for a hot path.

ARGON2_TIME_COST    = 3         # iterations
ARGON2_MEMORY_COST  = 65536     # KiB = 64 MB
ARGON2_PARALLELISM  = 4         # threads
ARGON2_HASH_LEN     = 32        # bytes — 256-bit output
ARGON2_SALT_LEN     = 16        # bytes — 128-bit random salt per hash

# Pre-configured PasswordHasher for server-side password verification.
# Uses the constants above so parameters are defined in one place.
_password_hasher = PasswordHasher(
    time_cost    = ARGON2_TIME_COST,
    memory_cost  = ARGON2_MEMORY_COST,
    parallelism  = ARGON2_PARALLELISM,
    hash_len     = ARGON2_HASH_LEN,
    salt_len     = ARGON2_SALT_LEN,
)


# ── HKDF ────────────────────────────────────────────────────────────────────

def hkdf_derive(
    ikm:    bytes,
    salt:   bytes,
    info:   bytes,
    length: int = 32,
) -> bytes:
    """
    Derive keying material using HKDF-SHA256 (RFC 5869).

    Always call this with one of the INFO_* constants defined above as the
    info parameter. Never pass an ad-hoc string — use a constant so the
    derivation context is auditable and domain-separated.

    Parameters
    ----------
    ikm    : input key material (e.g. DH output, shared secret)
    salt   : non-secret random value. Use os.urandom(32) for new derivations.
             For the Double Ratchet root KDF, the current root key is the salt.
    info   : domain separation string — must be one of the INFO_* constants.
    length : output length in bytes (default 32)

    Returns
    -------
    bytes : derived key material of the requested length

    Raises
    ------
    ValueError : if ikm or salt are empty, or length is not positive
    """
    if not ikm:
        raise ValueError("ikm must not be empty")
    if not salt:
        raise ValueError("salt must not be empty")
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if not info:
        raise ValueError(
            "info must not be empty — use one of the INFO_* constants "
            "to ensure domain separation"
        )

    return HKDF(
        algorithm = hashes.SHA256(),
        length    = length,
        salt      = salt,
        info      = info,
    ).derive(ikm)


def hkdf_derive_many(
    ikm:     bytes,
    salt:    bytes,
    info:    bytes,
    lengths: list[int],
) -> list[bytes]:
    """
    Derive multiple keys of different lengths from the same IKM in one call.

    Used when a single KDF step must produce multiple keys — for example,
    the Double Ratchet root KDF produces both a new root key (32 bytes) and
    a new chain key (32 bytes) simultaneously. Deriving them in a single
    HKDF call with a combined length guarantees they share the same PRF
    evaluation and are domain-separated from all other derivations.

    Parameters
    ----------
    ikm     : input key material
    salt    : non-secret random value or current root key
    info    : domain separation string — must be one of the INFO_* constants
    lengths : list of output lengths, one per key to derive

    Returns
    -------
    list[bytes] : one bytes object per entry in lengths, in the same order

    Example
    -------
    root_key, chain_key = hkdf_derive_many(
        ikm     = dh_output,
        salt    = current_root_key,
        info    = INFO_ROOT_KDF,
        lengths = [32, 32],
    )
    """
    if not lengths:
        raise ValueError("lengths must not be empty")
    if any(l <= 0 for l in lengths):
        raise ValueError("all lengths must be positive")

    total  = sum(lengths)
    raw    = hkdf_derive(ikm, salt, info, length=total)

    # Split the combined output into individual keys
    keys   = []
    offset = 0
    for l in lengths:
        keys.append(raw[offset : offset + l])
        offset += l
    return keys


# ── Argon2id — server-side password hashing ──────────────────────────────────

def argon2id_hash(password: str) -> str:
    """
    Hash a password for server-side storage using Argon2id.

    Returns an encoded hash string that includes the salt, parameters, and
    hash — everything needed for future verification. Store this string
    directly in the database. Never store the password itself.

    Parameters are set at module level (ARGON2_* constants) and justified
    against the OWASP Password Storage Cheat Sheet.

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
    """
    try:
        return _password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


# ── Argon2id — local key derivation ──────────────────────────────────────────
#
# This is separate from server-side password hashing. When a user's long-term
# private key bundle is stored encrypted on their device, the encryption key
# is derived from their passphrase using Argon2id with a LOCAL salt — distinct
# from the server-side salt. This means:
#
#   - A server database breach does not expose the local key encryption key.
#   - The server cannot derive the local encryption key even if it knows the
#     server-side hash, because the salts are different.
#
# The local salt is stored alongside the encrypted key bundle (it is not
# secret — it just prevents precomputation attacks).

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
