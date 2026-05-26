"""
tests/test_header_counter.py

Unit tests for core/header_counter.py

HeaderCounter is now an in-memory object. Persistence is handled by
StateStore — see test_state_store.py for counter persistence tests.

Run with: pytest testing/test_header_counter.py -v
"""

import struct
import pytest

from core.header_counter import (
    HeaderCounter,
    HeaderCounterError,
)
from core.constants import MAX_HEADER_MESSAGES, NONCE_LEN


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def counter():
    return HeaderCounter(session_id="session-abc")


# ── Construction ──────────────────────────────────────────────────────────────

class TestConstruction:

    def test_default_counter_starts_at_zero(self, counter):
        assert counter.current == 0

    def test_initial_value_respected(self):
        c = HeaderCounter(session_id="s", initial=42)
        assert c.current == 42

    def test_negative_initial_raises(self):
        with pytest.raises(ValueError):
            HeaderCounter(session_id="s", initial=-1)

    def test_initial_exceeding_max_raises(self):
        with pytest.raises(HeaderCounterError):
            HeaderCounter(session_id="s", initial=MAX_HEADER_MESSAGES + 1)

    def test_initial_at_max_is_accepted(self):
        """Counter at MAX is valid — next_nonce() will raise, not __init__."""
        c = HeaderCounter(session_id="s", initial=MAX_HEADER_MESSAGES)
        assert c.current == MAX_HEADER_MESSAGES

    def test_session_id_stored(self, counter):
        assert counter.session_id == "session-abc"

    def test_no_files_created(self, tmp_path):
        """
        HeaderCounter no longer manages files — StateStore does.
        Verify no files are created on construction.
        """
        import os
        before = set(os.listdir(tmp_path))
        HeaderCounter(session_id="s")
        after  = set(os.listdir(tmp_path))
        assert before == after


# ── next_nonce ────────────────────────────────────────────────────────────────

class TestNextNonce:

    def test_returns_nonce_len_bytes(self, counter):
        assert len(counter.next_nonce()) == NONCE_LEN

    def test_increments_counter(self, counter):
        counter.next_nonce()
        assert counter.current == 1

    def test_sequential_nonces_are_unique(self, counter):
        nonces = [counter.next_nonce() for _ in range(100)]
        assert len(set(nonces)) == 100

    def test_nonces_are_strictly_increasing(self, counter):
        values = []
        for _ in range(10):
            nonce = counter.next_nonce()
            value = struct.unpack("<Q", nonce[:8])[0]
            values.append(value)
        assert values == sorted(values)
        assert values == list(range(1, 11))

    def test_max_counter_raises(self):
        c = HeaderCounter(session_id="s", initial=MAX_HEADER_MESSAGES)
        with pytest.raises(HeaderCounterError, match="MAX_HEADER_MESSAGES"):
            c.next_nonce()

    def test_counter_unchanged_on_error(self):
        c = HeaderCounter(session_id="s", initial=MAX_HEADER_MESSAGES)
        with pytest.raises(HeaderCounterError):
            c.next_nonce()
        assert c.current == MAX_HEADER_MESSAGES


# ── Nonce encoding ────────────────────────────────────────────────────────────

class TestNonceEncoding:

    def test_first_nonce_encodes_counter_1(self, counter):
        nonce   = counter.next_nonce()
        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 1

    def test_trailing_bytes_are_zero(self, counter):
        nonce = counter.next_nonce()
        assert nonce[8:] == b"\x00" * (NONCE_LEN - 8)

    def test_nonce_at_counter_n_encodes_n(self, counter):
        for _ in range(42):
            nonce = counter.next_nonce()
        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 42


# ── Reset ─────────────────────────────────────────────────────────────────────

class TestReset:

    def test_reset_sets_counter_to_zero(self, counter):
        """
        Reset must be called when the DH ratchet step rotates the header key.
        The new key starts its counter at 0 — identical nonce values across
        different keys are not nonce reuse.
        """
        for _ in range(10):
            counter.next_nonce()
        assert counter.current == 10
        counter.reset()
        assert counter.current == 0

    def test_nonces_after_reset_start_from_one(self, counter):
        for _ in range(5):
            counter.next_nonce()
        counter.reset()
        nonce   = counter.next_nonce()
        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 1

    def test_reset_allows_reuse_of_nonce_values(self, counter):
        """
        After reset, nonce values repeat — but the header key has rotated
        so (key, nonce) pairs are still unique. This test documents that
        counter values alone are not the uniqueness guarantee; the key is.
        """
        n1 = counter.next_nonce()   # counter=1 under old key
        counter.reset()
        n2 = counter.next_nonce()   # counter=1 under new key
        assert n1 == n2             # same nonce bytes — different keys

    def test_counter_can_advance_normally_after_reset(self, counter):
        counter.next_nonce()
        counter.reset()
        for _ in range(5):
            counter.next_nonce()
        assert counter.current == 5


# ── Restore from persisted value ──────────────────────────────────────────────

class TestRestoreFromPersistedValue:

    def test_restored_counter_continues_from_saved_value(self):
        """
        Simulate saving counter value to StateStore and restoring it.
        The restored counter must continue from where it left off,
        not restart from 0.
        """
        original = HeaderCounter(session_id="s")
        for _ in range(7):
            original.next_nonce()

        saved_value = original.current   # = 7

        # Simulate process restart — create new counter from saved value
        restored = HeaderCounter(session_id="s", initial=saved_value)
        nonce    = restored.next_nonce()

        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 8   # continues from 7, not 1

    def test_restored_counter_does_not_reuse_previous_nonces(self):
        """
        Nonces produced before saving must not appear again after restore.
        """
        original = HeaderCounter(session_id="s")
        pre_restore_nonces = {original.next_nonce() for _ in range(5)}

        restored = HeaderCounter(session_id="s", initial=original.current)
        post_restore_nonces = {restored.next_nonce() for _ in range(5)}

        assert pre_restore_nonces.isdisjoint(post_restore_nonces)
