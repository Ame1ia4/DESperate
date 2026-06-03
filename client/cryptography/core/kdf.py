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
      time_cost   = 1   iteration
      memory_cost = 47104 KiB (≈ 46 MiB)
      parallelism = 1   thread
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

# SRP synthetic password — the password fed into SRP so that the verifier is
# protected by Argon2id rather than only SHA-256. Must differ from all other
# INFO_* constants to ensure key independence.
INFO_SRP_AUTH           = b"srp-v1-auth"

# Fail-fast: every INFO_* string must be unique — a collision means two keys
# share the same derivation and are cryptographically identical.
_ALL_INFO = [
    INFO_PQXDH_SK, INFO_ROOT_KDF, INFO_CHAIN_KDF, INFO_HEADER_KEY,
    INFO_LOCAL_KEY_ENC, INFO_LOCAL_KEY_MASTER, INFO_SRP_AUTH,
]
assert len(_ALL_INFO) == len(set(_ALL_INFO)), "Duplicate HKDF INFO constant — keys are not independent"
del _ALL_INFO


# Argon2id functions have moved to core/password.py.
# Re-exported here so existing callers importing from core.kdf continue to work.
from .password import argon2id_hash, argon2id_verify, argon2id_derive_key

# Argon2id parameter constants live in core/constants.py.
# Re-exported here so existing callers importing from core.kdf continue to work
# (e.g. core/state_store.py, testing/test_kdf.py).
from .constants import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
    ARGON2_SALT_LEN,
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


def derive_master_components(
    password: str,
    salt:     bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """
    Derive SRP synthetic password and keystore encryption key from one Argon2id call.

    Run Argon2id once on the master password, then use HKDF with distinct info
    strings to produce two independent sub-keys.  The same salt must be used on
    every login — pass the srp_salt returned by /auth/init (which equals the salt
    generated during registration and stored on the server).

    Parameters
    ----------
    password : the user's master password
    salt     : ARGON2_SALT_LEN-byte salt. Generated freshly when None (registration).
               Must be the server-returned srp_salt on subsequent calls (login).

    Returns
    -------
    (srp_pass, keystore_key, salt) — all bytes
        srp_pass    : 32 bytes; encode as .hex() before passing to SrpSession
        keystore_key: 32 bytes; use directly as ChaCha20-Poly1305 key
        salt        : the salt used — send to server as srp_salt on first call
    """
    master_key, used_salt = argon2id_derive_key(password, salt)
    srp_pass     = hkdf_derive(master_key, used_salt, INFO_SRP_AUTH)
    keystore_key = hkdf_derive(master_key, used_salt, INFO_LOCAL_KEY_ENC)
    return srp_pass, keystore_key, used_salt


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

