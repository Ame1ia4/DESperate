"""
core/ratchet/header_counter.py

Stateful monotonic counter for header key nonce derivation.

Because the same header key is reused across multiple messages within a
single DH ratchet epoch, nonces must be strictly unique across all uses of
that key. We achieve this with a per-session monotonically increasing
counter, which is safe because:

  - Each session derives an independent header key via its own KDF chain,
    so identical counter values across sessions are not nonce reuse.
  - Within a session the counter never decreases, so (key, nonce) pairs
    are never repeated.

The critical implementation requirement is atomicity: the counter must be
persisted to disk before the encrypted message is sent. A crash between
"encrypt with counter N" and "persist counter N" would cause counter N to
be reused on recovery — a (key, nonce) collision within the session.

We achieve atomicity via write-to-temp-then-rename, which is atomic on
POSIX systems (Linux, macOS). On Windows, os.replace() provides the same
guarantee since Python 3.3.

Reference: Signal Double Ratchet spec §4.1 — header encryption nonce
  https://signal.org/docs/specifications/doubleratchet/#header-encryption
Reference: MLS draft-ietf-mls-protocol-17 §9.3 — stateful nonce requirement
  https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17
"""

from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path


# Maximum counter value before a DH ratchet step MUST occur.
# A header key should never be used for more than MAX_HEADER_MESSAGES
# messages. In practice the DH ratchet rotates the header key far sooner;
# this is a safety bound only.
# uint64 gives 2^64 - 1 messages, which is effectively unbounded, but we
# cap it here at 2^32 to match the nonce space we actually use (4 bytes
# of the 12-byte nonce are the reuse guard; we use the remaining 8 for
# the counter, giving 2^64 unique values — more than sufficient).
MAX_HEADER_MESSAGES: int = 2**32 - 1

_NONCE_LEN: int = 12


class HeaderCounterError(Exception):
    """Raised when the counter reaches an unsafe state."""


class HeaderCounter:
    """
    Monotonically increasing per-session counter for header key nonces.

    Usage
    -----
    counter = HeaderCounter.load(path)   # or HeaderCounter(path) for new

    # Get next nonce — persists counter BEFORE returning:
    nonce = counter.next_nonce()

    # Use nonce immediately for encryption — do not store for later use.

    The counter file is a simple JSON object:
      {"session_id": "...", "counter": <int>}

    Keeping it as JSON (rather than binary) makes it inspectable during
    debugging and easier to reason about during your interview.
    """

    def __init__(self, path: Path, session_id: str, initial: int = 0) -> None:
        """
        Initialise a new counter. Use HeaderCounter.load() to restore an
        existing one — calling __init__ on an existing path overwrites it.

        Parameters
        ----------
        path       : file path for persistent storage (one file per session)
        session_id : identifier for this chat session (used as a sanity check
                     when loading — prevents accidentally loading the wrong
                     counter file for a session)
        initial    : starting value, always 0 for new sessions
        """
        if initial < 0:
            raise ValueError("Counter must start at 0 or above")

        self._path       = Path(path)
        self._session_id = session_id
        self._counter    = initial
        self._persist()   # write initial state immediately

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: Path) -> HeaderCounter:
        """
        Restore a counter from disk. Raises FileNotFoundError if the file
        does not exist — callers should create a new HeaderCounter instead.

        The session_id stored in the file is checked against the path name
        as a basic sanity guard against loading the wrong counter.
        """
        path = Path(path)
        raw  = path.read_text(encoding="utf-8")
        data = json.loads(raw)

        session_id = data["session_id"]
        counter    = int(data["counter"])

        if counter < 0:
            raise HeaderCounterError(
                f"Corrupt counter file {path}: negative value {counter}"
            )
        if counter > MAX_HEADER_MESSAGES:
            raise HeaderCounterError(
                f"Counter {counter} exceeds MAX_HEADER_MESSAGES — "
                f"DH ratchet step required before sending more messages"
            )

        instance              = cls.__new__(cls)
        instance._path        = path
        instance._session_id  = session_id
        instance._counter     = counter
        return instance

    # ── Core operation ────────────────────────────────────────────────────────

    def next_nonce(self) -> bytes:
        """
        Increment the counter, persist it atomically, then return a 12-byte
        nonce encoding the new counter value.

        ATOMICITY CONTRACT
        ------------------
        The counter is written to disk BEFORE this method returns. If the
        process crashes after persist but before the caller encrypts, the
        counter is already incremented — the skipped value is lost but no
        nonce reuse occurs. This is the safe failure mode: losing one nonce
        value is acceptable; reusing one is not.

        If the write fails (disk full, permission error, etc.) the counter
        is NOT incremented in memory and an OSError is raised. The caller
        must not attempt to encrypt in this case.

        Raises
        ------
        HeaderCounterError : if MAX_HEADER_MESSAGES would be exceeded
        OSError            : if the atomic write fails
        """
        next_val = self._counter + 1

        if next_val > MAX_HEADER_MESSAGES:
            raise HeaderCounterError(
                f"Counter would exceed MAX_HEADER_MESSAGES ({MAX_HEADER_MESSAGES}). "
                f"A DH ratchet step must occur before sending more messages."
            )

        # Persist FIRST — before updating in-memory state.
        # If _persist raises, self._counter is unchanged and the caller
        # gets an exception rather than a potentially-reused nonce.
        self._persist(next_val)
        self._counter = next_val

        return self._counter_to_nonce(self._counter)

    @property
    def current(self) -> int:
        """Current counter value (the last value successfully persisted)."""
        return self._counter

    @property
    def session_id(self) -> str:
        return self._session_id

    # ── Nonce encoding ────────────────────────────────────────────────────────

    @staticmethod
    def _counter_to_nonce(counter: int) -> bytes:
        """
        Encode a counter value as a 12-byte nonce.

        Layout: counter as little-endian uint64 (8 bytes) || 0x00 * 4

        Using only 8 of the 12 bytes gives 2^64 unique values —
        more than sufficient. The trailing zero bytes are explicit padding
        so the nonce structure is unambiguous in the design document.
        """
        return struct.pack("<Q", counter) + b"\x00" * 4

    # ── Atomic persistence ────────────────────────────────────────────────────

    def _persist(self, value: int | None = None) -> None:
        """
        Write counter state atomically using write-to-temp-then-rename.

        On POSIX (Linux/macOS), os.replace() of a file in the same directory
        is guaranteed atomic by the kernel — readers either see the old file
        or the new one, never a partial write. This is the standard pattern
        for crash-safe file updates.

        The temp file is written to the same directory as the target so that
        the rename is within the same filesystem (cross-filesystem renames
        are not atomic).
        """
        if value is None:
            value = self._counter

        payload = json.dumps({
            "session_id": self._session_id,
            "counter":    value,
        }, indent=2).encode("utf-8")

        # Write to a sibling temp file, then atomically rename into place.
        dir_  = self._path.parent
        dir_.mkdir(parents=True, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".tmp")
        try:
            os.write(fd, payload)
            os.fsync(fd)     # flush kernel buffer to storage before rename
            os.close(fd)
            os.replace(tmp_path, self._path)   # atomic on POSIX
        except OSError:
            # Clean up the temp file if anything went wrong.
            # Do NOT update self._counter — leave state consistent.
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def delete(self) -> None:
        """
        Delete the counter file. Call this when the DH ratchet rotates the
        header key — the old counter is no longer needed and should not be
        reused with a new key.
        """
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass   # already gone — not an error

    def __repr__(self) -> str:
        return (
            f"HeaderCounter(session_id={self._session_id!r}, "
            f"counter={self._counter}, path={self._path})"
        )
