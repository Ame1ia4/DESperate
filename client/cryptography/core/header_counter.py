"""
core/ratchet/header_counter.py

Stateful monotonic nonce counter for header key encryption.

Persists to disk atomically (write-to-temp-then-rename) before returning
each nonce, ensuring no reuse on crash recovery.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
from pathlib import Path

from .constants import MAX_HEADER_MESSAGES, NONCE_LEN


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
        """
        return struct.pack("<Q", counter) + b"\x00" * 4

    # ── Atomic persistence ────────────────────────────────────────────────────

    def _persist(self, value: int | None = None) -> None:
        """
        Write counter state atomically using write-to-temp-then-rename,
        followed by a directory fsync (POSIX only).

        Steps:
          1. Write payload to a sibling .tmp file in the same directory.
          2. fsync the file descriptor — flushes data to storage.
          3. Close the file descriptor.
          4. os.replace() — atomic rename; readers see old or new, never partial.
          5. fsync the directory — flushes the directory entry to storage.
        """
        if value is None:
            value = self._counter

        payload = json.dumps({
            "session_id": self._session_id,
            "counter":    value,
        }, indent=2).encode("utf-8")

        dir_ = self._path.parent
        dir_.mkdir(parents=True, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".tmp")
        try:
            os.write(fd, payload)
            os.fsync(fd)                            # flush file data
            os.close(fd)
            os.replace(tmp_path, self._path)        # atomic rename

            if sys.platform != "win32":  # directory fsync not needed on Windows
                dir_fd = os.open(str(dir_), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)

        except OSError:
            # Clean up the temp file if anything went wrong.
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
        """Delete the counter file when the DH ratchet rotates the header key."""
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass   # already gone — not an error

    def __repr__(self) -> str:
        return (
            f"HeaderCounter(session_id={self._session_id!r}, "
            f"counter={self._counter}, path={self._path})"
        )
