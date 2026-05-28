"""
core/header_counter.py

In-memory monotonic counter for header key nonce derivation.

Because the same header key is reused across multiple messages within a
single DH ratchet epoch, nonces must be strictly unique across all uses of
that key. We achieve this with a per-session monotonically increasing counter.

PERSISTENCE
  Counter values are no longer persisted by this class directly. Persistence
  is handled by StateStore (core/state_store.py), which saves the counter
  value as part of the encrypted session state on every increment. This
  consolidates all session-scoped persistence into one place and gives the
  counter the same atomicity and tamper detection as the ratchet state itself.

  The ratchet session layer is responsible for:
    1. Loading the counter value from StateStore on session load
    2. Calling StateStore.save_state() after every counter.next_nonce() call
    3. Passing the counter value to StateStore when saving session state

ATOMICITY
  Because persistence is now handled by StateStore (which uses atomic
  write-to-temp-then-rename), the counter value on disk is always consistent
  with the last successfully persisted ratchet state. A crash mid-write
  leaves the previous state intact — the counter value is never partially
  written.

NONCE UNIQUENESS
  - Across sessions: each session derives an independent header key, so
    identical counter values in different sessions are not nonce reuse.
  - Within a session: the counter is strictly increasing and never resets
    for the lifetime of a header key epoch.
  - On DH ratchet step: the header key rotates. The counter MUST be reset
    to 0 for the new key. The ratchet session layer is responsible for this.

Reference: Signal Double Ratchet spec §4.1 — header encryption nonce
  https://signal.org/docs/specifications/doubleratchet/#header-encryption
Reference: MLS draft-ietf-mls-protocol-17 §9.3 — stateful nonce requirement
  https://datatracker.ietf.org/doc/html/draft-ietf-mls-protocol-17
"""

from __future__ import annotations

import struct

from core.constants import MAX_HEADER_MESSAGES, NONCE_LEN


class HeaderCounterError(Exception):
    """Raised when the counter reaches an unsafe state."""


class HeaderCounter:
    """
    In-memory monotonic counter for header key nonces.

    Persistence is delegated to StateStore — the ratchet session layer
    saves the counter value as part of session state after every increment.

    Usage
    -----
    # Create fresh counter for a new header key epoch
    counter = HeaderCounter(session_id="session-abc")

    # Restore counter from persisted value (loaded from StateStore)
    counter = HeaderCounter(session_id="session-abc", initial=saved_value)

    # Get next nonce — caller must persist state immediately after
    nonce = counter.next_nonce()
    store.save_state(session_id, {
        ...,
        "header_counter": counter.current,
    })

    # On DH ratchet step — reset counter for new header key
    counter.reset()
    """

    def __init__(self, session_id: str, initial: int = 0) -> None:
        """
        Parameters
        ----------
        session_id : identifier for the owning session (used in repr/errors)
        initial    : starting counter value. Pass the value loaded from
                     StateStore when restoring an existing session.
                     Always 0 for a new session or after a DH ratchet step.
        """
        if initial < 0:
            raise ValueError("Counter must start at 0 or above")
        if initial > MAX_HEADER_MESSAGES:
            raise HeaderCounterError(
                f"initial value {initial} exceeds MAX_HEADER_MESSAGES "
                f"({MAX_HEADER_MESSAGES}) — DH ratchet step required"
            )

        self._session_id = session_id
        self._counter    = initial

    # ── Core operation ────────────────────────────────────────────────────────

    def next_nonce(self) -> bytes:
        """
        Increment the counter and return a NONCE_LEN-byte nonce.

        IMPORTANT: The caller must persist the updated counter value to
        StateStore immediately after this call returns, before using the
        nonce for encryption. Failure to do so risks nonce reuse if the
        process crashes between next_nonce() and the next save_state().

        Returns
        -------
        bytes : NONCE_LEN-byte nonce encoding the new counter value

        Raises
        ------
        HeaderCounterError : if MAX_HEADER_MESSAGES would be exceeded
        """
        next_val = self._counter + 1

        if next_val > MAX_HEADER_MESSAGES:
            raise HeaderCounterError(
                f"Counter would exceed MAX_HEADER_MESSAGES "
                f"({MAX_HEADER_MESSAGES}) for session {self._session_id!r}. "
                f"A DH ratchet step must occur before sending more messages."
            )

        self._counter = next_val
        return self._counter_to_nonce(self._counter)

    def reset(self) -> None:
        """
        Reset counter to 0 for a new header key epoch.

        Call this when the DH ratchet step rotates the header key.
        The new key starts at counter=0 — the old (key, nonce) pairs
        are no longer reachable since the key itself has changed.

        The caller must persist the reset value to StateStore immediately.
        """
        self._counter = 0

    @property
    def current(self) -> int:
        """
        Current counter value.

        This is the value to save into StateStore when persisting session
        state — pass it as "header_counter" in the state dict.
        """
        return self._counter

    @property
    def session_id(self) -> str:
        return self._session_id

    # ── Nonce encoding ────────────────────────────────────────────────────────

    @staticmethod
    def _counter_to_nonce(counter: int) -> bytes:
        """
        Encode a counter value as a NONCE_LEN-byte nonce.

        Layout: counter as little-endian uint64 (8 bytes) || 0x00 * 4

        Using 8 of the 12 bytes gives 2^64 unique values per header key
        epoch — far beyond any realistic session length. The trailing zero
        bytes are explicit padding so the nonce layout is unambiguous in
        the design document.
        """
        return struct.pack("<Q", counter) + b"\x00" * (NONCE_LEN - 8)

    def __repr__(self) -> str:
        return (
            f"HeaderCounter(session_id={self._session_id!r}, "
            f"counter={self._counter})"
        )
