"""
core/state_store.py

Encrypted persistent storage for ratchet state and session metadata.

Every value written to disk is encrypted under ChaCha20-Poly1305 using a
key derived from the user's passphrase via Argon2id + HKDF. Plaintext
ratchet state never touches disk — a stolen device without the passphrase
cannot recover session keys or message history.

STORAGE LAYOUT
  base_dir/
    salt                        — 16-byte Argon2id salt (plaintext, not secret)
    sessions/
      <session_id>.state        — encrypted ratchet state (JSON)
      <session_id>.meta         — encrypted session metadata (JSON)

  Each file is a self-contained encrypted blob:
    nonce (12 bytes) || ciphertext || tag (16 bytes)

  The associated data for every file includes the session_id and file type,
  binding the ciphertext to its intended location — a file cannot be moved
  to a different session and decrypted successfully.

ATOMICITY
  All writes use the same write-to-temp-then-rename pattern as HeaderCounter:
  data is written to a .tmp sibling, fsynced, then atomically renamed into
  place. On POSIX a directory fsync follows to persist the rename itself.
  This prevents corrupt state from a crash mid-write.

THREAD SAFETY
  Not thread-safe. The ratchet session layer is responsible for ensuring
  only one coroutine/thread accesses a given session store at a time.

References:
  PQXDH spec (key storage):   https://signal.org/docs/specifications/pqxdh/
  RFC 9106 (Argon2):          https://www.rfc-editor.org/rfc/rfc9106
  RFC 8439 (ChaCha20):        https://www.rfc-editor.org/rfc/rfc8439
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from core.constants import NONCE_LEN, TAG_LEN
from core.kdf import (
    argon2id_derive_key,
    hkdf_derive,
    INFO_LOCAL_KEY_ENC,
    ARGON2_SALT_LEN,
)


# ── Constants ────────────────────────────────────────────────────────────────

# File names within the session directory
_SALT_FILE    = "salt"
_STATE_SUFFIX = ".state"
_META_SUFFIX  = ".meta"
_TMP_SUFFIX   = ".tmp"

_MIN_BLOB_LEN = NONCE_LEN + TAG_LEN   # minimum valid encrypted file size


# ── Session metadata dataclass ────────────────────────────────────────────────

@dataclass
class SessionMetadata:
    """
    Non-cryptographic metadata about a messaging session.

    Stored encrypted alongside ratchet state. Contains enough information
    to display session listings and manage session lifecycle without
    decrypting the full ratchet state.

    Fields
    ------
    session_id    : unique identifier for this session (e.g. UUID)
    remote_user   : the other party's user ID
    created_at    : Unix timestamp of session creation
    last_active   : Unix timestamp of last sent/received message
    message_count : total messages sent + received in this session
    is_initiator  : True if we initiated the session (Alice), False if Bob
    opk_id_used   : OPK consumed during PQXDH initiation, or None
    """
    session_id:    str
    remote_user:   str
    created_at:    float
    last_active:   float
    message_count: int  = 0
    is_initiator:  bool = True
    opk_id_used:   Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "session_id":    self.session_id,
            "remote_user":   self.remote_user,
            "created_at":    self.created_at,
            "last_active":   self.last_active,
            "message_count": self.message_count,
            "is_initiator":  self.is_initiator,
            "opk_id_used":   self.opk_id_used,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SessionMetadata:
        return cls(
            session_id    = d["session_id"],
            remote_user   = d["remote_user"],
            created_at    = float(d["created_at"]),
            last_active   = float(d["last_active"]),
            message_count = int(d.get("message_count", 0)),
            is_initiator  = bool(d.get("is_initiator", True)),
            opk_id_used   = d.get("opk_id_used"),
        )


# ── StateStore ────────────────────────────────────────────────────────────────

class StateStore:
    """
    Encrypted persistent storage for ratchet state and session metadata.

    Usage
    -----
    # First use — creates base_dir and derives encryption key from passphrase
    store = StateStore.create(base_dir, passphrase="user_passphrase")

    # Subsequent uses — loads existing salt and re-derives the same key
    store = StateStore.load(base_dir, passphrase="user_passphrase")

    # Save ratchet state for a session
    store.save_state(session_id, ratchet_state_dict)

    # Load ratchet state
    state = store.load_state(session_id)

    # Save session metadata
    store.save_metadata(session_id, metadata)

    # Load session metadata
    meta = store.load_metadata(session_id)

    # List all known session IDs
    sessions = store.list_sessions()

    # Delete a session (state + metadata)
    store.delete_session(session_id)
    """

    def __init__(self, base_dir: Path, enc_key: bytes) -> None:
        """
        Internal — use StateStore.create() or StateStore.load() instead.

        Parameters
        ----------
        base_dir : root directory for all state files
        enc_key  : 32-byte encryption key derived from the user's passphrase
        """
        self._base_dir  = Path(base_dir)
        self._enc_key   = enc_key
        self._sess_dir  = self._base_dir / "sessions"
        self._sess_dir.mkdir(parents=True, exist_ok=True)

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def create(cls, base_dir: Path, passphrase: str) -> StateStore:
        """
        Create a new StateStore at base_dir.

        Generates a fresh Argon2id salt, derives the encryption key, and
        writes the salt to disk. Call this once on first run / registration.

        Parameters
        ----------
        base_dir   : directory to store state files (created if absent)
        passphrase : user's local passphrase — used to derive enc_key
        """
        base_dir = Path(base_dir)
        base_dir.mkdir(parents=True, exist_ok=True)

        salt_path = base_dir / _SALT_FILE
        if salt_path.exists():
            raise FileExistsError(
                f"StateStore already exists at {base_dir}. "
                f"Use StateStore.load() instead."
            )

        # Generate fresh salt and derive encryption key
        raw_key, salt = argon2id_derive_key(passphrase)
        enc_key       = hkdf_derive(raw_key, salt, INFO_LOCAL_KEY_ENC)

        # Write salt atomically — it is not secret but must not be corrupted
        _atomic_write(salt_path, salt)

        return cls(base_dir, enc_key)

    @classmethod
    def load(cls, base_dir: Path, passphrase: str) -> StateStore:
        """
        Load an existing StateStore from base_dir.

        Reads the stored Argon2id salt and re-derives the encryption key
        from the passphrase. The same passphrase always produces the same
        key for a given salt.

        Parameters
        ----------
        base_dir   : directory containing existing state files
        passphrase : must match the passphrase used with create()

        Raises
        ------
        FileNotFoundError : if base_dir or salt file does not exist
        """
        base_dir  = Path(base_dir)
        salt_path = base_dir / _SALT_FILE

        if not salt_path.exists():
            raise FileNotFoundError(
                f"No StateStore found at {base_dir}. "
                f"Use StateStore.create() for first use."
            )

        salt    = salt_path.read_bytes()
        if len(salt) != ARGON2_SALT_LEN:
            raise ValueError(
                f"Corrupt salt file: expected {ARGON2_SALT_LEN} bytes, "
                f"got {len(salt)}"
            )

        raw_key, _ = argon2id_derive_key(passphrase, salt)
        enc_key    = hkdf_derive(raw_key, salt, INFO_LOCAL_KEY_ENC)

        return cls(base_dir, enc_key)

    @classmethod
    def create_with_key(cls, base_dir: Path, enc_key: bytes, master_salt: bytes) -> StateStore:
        """
        Create a new StateStore using a pre-derived encryption key.

        Use this when Argon2id has already been run externally (master-password
        flow) to avoid a second expensive derivation.  master_salt is written
        to disk so that the salt file remains present for load_with_key checks.

        Parameters
        ----------
        base_dir    : directory to store state files (created if absent)
        enc_key     : 32-byte encryption key already derived via HKDF
        master_salt : the Argon2id salt used in that derivation (persisted)
        """
        if len(master_salt) != ARGON2_SALT_LEN:
            raise ValueError(
                f"master_salt must be {ARGON2_SALT_LEN} bytes, got {len(master_salt)}"
            )
        base_dir  = Path(base_dir)
        base_dir.mkdir(parents=True, exist_ok=True)
        salt_path = base_dir / _SALT_FILE
        if salt_path.exists():
            raise FileExistsError(
                f"StateStore already exists at {base_dir}. "
                f"Use StateStore.load_with_key() instead."
            )
        _atomic_write(salt_path, master_salt)
        return cls(base_dir, enc_key)

    @classmethod
    def load_with_key(cls, base_dir: Path, enc_key: bytes) -> StateStore:
        """
        Load an existing StateStore using a pre-derived encryption key.

        Use this when Argon2id has already been run externally (master-password
        flow).  The salt file must exist (written by create_with_key or create).

        Parameters
        ----------
        base_dir : directory containing existing state files
        enc_key  : 32-byte encryption key already derived via HKDF
        """
        base_dir  = Path(base_dir)
        salt_path = base_dir / _SALT_FILE
        if not salt_path.exists():
            raise FileNotFoundError(
                f"No StateStore found at {base_dir}. "
                f"Use StateStore.create_with_key() for first use."
            )
        salt = salt_path.read_bytes()
        if len(salt) != ARGON2_SALT_LEN:
            raise ValueError(
                f"Corrupt salt file: expected {ARGON2_SALT_LEN} bytes, "
                f"got {len(salt)}"
            )
        return cls(base_dir, enc_key)

    # ── Ratchet state ─────────────────────────────────────────────────────────

    def save_state(self, session_id: str, state: dict) -> None:
        """
        Encrypt and persist ratchet state for a session.

        The state dict is serialised to JSON, encrypted, and written
        atomically. The previous state file is replaced only after the
        new file is fully written and fsynced.

        Parameters
        ----------
        session_id : unique session identifier
        state      : ratchet state dict (from python-doubleratchet's
                     serialisation or your own state dataclass)
        """
        _validate_session_id(session_id)
        path    = self._state_path(session_id)
        payload = json.dumps(state, separators=(",", ":")).encode("utf-8")
        ad      = _make_ad(session_id, "state")
        self._encrypt_write(path, payload, ad)

    def load_state(self, session_id: str) -> dict:
        """
        Load and decrypt ratchet state for a session.

        Parameters
        ----------
        session_id : unique session identifier

        Returns
        -------
        dict : ratchet state as originally passed to save_state()

        Raises
        ------
        FileNotFoundError : if no state exists for this session
        InvalidTag        : if the file has been tampered with
        """
        _validate_session_id(session_id)
        path = self._state_path(session_id)

        if not path.exists():
            raise FileNotFoundError(
                f"No ratchet state found for session {session_id!r}"
            )

        ad      = _make_ad(session_id, "state")
        payload = self._read_decrypt(path, ad)
        return json.loads(payload.decode("utf-8"))

    def state_exists(self, session_id: str) -> bool:
        """Return True if ratchet state exists for this session."""
        return self._state_path(session_id).exists()

    # ── Session metadata ──────────────────────────────────────────────────────

    def save_metadata(self, session_id: str, meta: SessionMetadata) -> None:
        """
        Encrypt and persist session metadata.

        Parameters
        ----------
        session_id : unique session identifier
        meta       : SessionMetadata instance
        """
        _validate_session_id(session_id)
        path    = self._meta_path(session_id)
        payload = json.dumps(
            meta.to_dict(), separators=(",", ":")
        ).encode("utf-8")
        ad      = _make_ad(session_id, "meta")
        self._encrypt_write(path, payload, ad)

    def load_metadata(self, session_id: str) -> SessionMetadata:
        """
        Load and decrypt session metadata.

        Raises
        ------
        FileNotFoundError : if no metadata exists for this session
        InvalidTag        : if the file has been tampered with
        """
        _validate_session_id(session_id)
        path = self._meta_path(session_id)

        if not path.exists():
            raise FileNotFoundError(
                f"No metadata found for session {session_id!r}"
            )

        ad      = _make_ad(session_id, "meta")
        payload = self._read_decrypt(path, ad)
        return SessionMetadata.from_dict(json.loads(payload.decode("utf-8")))

    def metadata_exists(self, session_id: str) -> bool:
        """Return True if metadata exists for this session."""
        return self._meta_path(session_id).exists()

    # ── Session lifecycle ─────────────────────────────────────────────────────

    def list_sessions(self) -> list[str]:
        """
        Return a list of all session IDs with persisted state.

        Only sessions with a .state file are included — sessions with
        only metadata (e.g. from an incomplete initiation) are excluded.
        """
        return [
            p.stem
            for p in self._sess_dir.glob(f"*{_STATE_SUFFIX}")
        ]

    def delete_session(self, session_id: str) -> None:
        """
        Delete all persisted data for a session (state + metadata).

        Safe to call even if one or both files are missing.
        After deletion, the session's ratchet state is unrecoverable.
        """
        _validate_session_id(session_id)
        for path in [self._state_path(session_id),
                     self._meta_path(session_id)]:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


    # ── Header counter ────────────────────────────────────────────────────────
    #
    # The header counter value is stored as part of the encrypted session state
    # rather than in a separate file. This consolidates all session-scoped
    # persistence into one place and gives the counter the same atomicity and
    # tamper detection as the ratchet state itself.
    #
    # Convention: the counter value is stored under the key "header_counter"
    # in the session state dict. The ratchet session layer is responsible for
    # reading and writing this key when saving/loading session state.

    def save_counter(self, session_id: str, counter_value: int) -> None:
        """
        Persist the header counter value for a session.

        Loads existing state, updates the "header_counter" key, and saves
        atomically. If no state exists yet, creates a minimal state dict
        containing only the counter.

        The caller must ensure counter_value is the value AFTER incrementing
        — never call this with the pre-increment value.

        Parameters
        ----------
        session_id    : unique session identifier
        counter_value : current HeaderCounter.current value after next_nonce()
        """
        _validate_session_id(session_id)

        # Load existing state if present, otherwise start with empty dict
        if self.state_exists(session_id):
            state = self.load_state(session_id)
        else:
            state = {}

        state["header_counter"] = counter_value
        self.save_state(session_id, state)

    def load_counter(self, session_id: str) -> int:
        """
        Load the persisted header counter value for a session.

        Returns 0 if no counter has been saved yet (new session or after
        a DH ratchet step that reset the counter).

        Parameters
        ----------
        session_id : unique session identifier

        Returns
        -------
        int : last persisted counter value, or 0 if not found
        """
        _validate_session_id(session_id)

        if not self.state_exists(session_id):
            return 0

        state = self.load_state(session_id)
        return int(state.get("header_counter", 0))

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _state_path(self, session_id: str) -> Path:
        return self._sess_dir / f"{session_id}{_STATE_SUFFIX}"

    def _meta_path(self, session_id: str) -> Path:
        return self._sess_dir / f"{session_id}{_META_SUFFIX}"

    def _encrypt_write(self, path: Path, plaintext: bytes, ad: bytes) -> None:
        """
        Encrypt plaintext and write to path atomically.

        Wire format: nonce (12) || ciphertext || tag (16)
        """
        nonce      = os.urandom(NONCE_LEN)
        ciphertext = ChaCha20Poly1305(self._enc_key).encrypt(
            nonce, plaintext, ad
        )
        blob = nonce + ciphertext
        _atomic_write(path, blob)

    def _read_decrypt(self, path: Path, ad: bytes) -> bytes:
        """
        Read an encrypted blob from path and decrypt it.

        Raises InvalidTag if authentication fails — either the file has
        been tampered with or the wrong passphrase was used.
        """
        blob = path.read_bytes()

        if len(blob) < _MIN_BLOB_LEN:
            raise ValueError(
                f"Encrypted file too short: {path} "
                f"({len(blob)} bytes, minimum {_MIN_BLOB_LEN})"
            )

        nonce      = blob[:NONCE_LEN]
        ciphertext = blob[NONCE_LEN:]

        return ChaCha20Poly1305(self._enc_key).decrypt(nonce, ciphertext, ad)

    def __repr__(self) -> str:
        return f"StateStore(base_dir={self._base_dir!r})"


# ── Module-level helpers ──────────────────────────────────────────────────────

def _make_ad(session_id: str, file_type: str) -> bytes:
    """
    Build associated data for AEAD binding a file to its session and type.

    Includes session_id and file_type so a .state file cannot be
    decrypted as a .meta file, and a file from one session cannot be
    moved to another session directory and decrypted successfully.

    Format: "statestore-v1:<file_type>:<session_id>"
    """
    return f"statestore-v1:{file_type}:{session_id}".encode("utf-8")


def _validate_session_id(session_id: str) -> None:
    """
    Reject session IDs that would escape the sessions/ directory.

    Prevents path traversal attacks where a crafted session_id like
    "../../etc/passwd" could write outside the intended directory.
    """
    if not session_id:
        raise ValueError("session_id must not be empty")
    forbidden = set('/\\:*?"<>|')
    if any(c in forbidden for c in session_id):
        raise ValueError(
            f"session_id contains forbidden characters: {session_id!r}"
        )
    if session_id.startswith("."):
        raise ValueError(
            f"session_id must not start with '.': {session_id!r}"
        )


def _atomic_write(path: Path, data: bytes) -> None:
    """
    Write data to path atomically using write-to-temp-then-rename.

    On POSIX a directory fsync follows the rename to ensure the directory
    entry is durable. On Windows, MoveFileExW is transactional on NTFS
    so no directory fsync is needed.
    """
    dir_ = path.parent
    dir_.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=_TMP_SUFFIX)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp_path, path)

        if sys.platform != "win32":
            dir_fd = os.open(str(dir_), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
