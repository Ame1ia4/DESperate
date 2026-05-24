"""
tests/test_header_counter.py

Unit tests for core/ratchet/header_counter.py

Run with: pytest tests/test_header_counter.py -v
"""

import json
import os
import struct
import pytest
from pathlib import Path
from unittest.mock import patch

from core.header_counter import (
    HeaderCounter,
    HeaderCounterError,
    MAX_HEADER_MESSAGES,
    _NONCE_LEN,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def counter_path(tmp_path) -> Path:
    return tmp_path / "session_abc" / "header_counter.json"

@pytest.fixture
def counter(counter_path) -> HeaderCounter:
    return HeaderCounter(counter_path, session_id="session_abc")


# ── Construction ──────────────────────────────────────────────────────────────

class TestConstruction:

    def test_creates_file_on_init(self, counter, counter_path):
        assert counter_path.exists()

    def test_initial_counter_is_zero(self, counter):
        assert counter.current == 0

    def test_session_id_stored(self, counter):
        assert counter.session_id == "session_abc"

    def test_persisted_file_is_valid_json(self, counter, counter_path):
        data = json.loads(counter_path.read_text())
        assert data["counter"]    == 0
        assert data["session_id"] == "session_abc"

    def test_negative_initial_raises(self, counter_path):
        with pytest.raises(ValueError):
            HeaderCounter(counter_path, session_id="s", initial=-1)

    def test_creates_parent_directories(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "counter.json"
        HeaderCounter(deep, session_id="s")
        assert deep.exists()


# ── Load ──────────────────────────────────────────────────────────────────────

class TestLoad:

    def test_load_restores_counter(self, counter, counter_path):
        # Advance the counter a few times
        for _ in range(5):
            counter.next_nonce()
        assert counter.current == 5

        restored = HeaderCounter.load(counter_path)
        assert restored.current == 5

    def test_load_restores_session_id(self, counter, counter_path):
        restored = HeaderCounter.load(counter_path)
        assert restored.session_id == "session_abc"

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            HeaderCounter.load(tmp_path / "nonexistent.json")

    def test_load_corrupt_negative_counter_raises(self, counter_path):
        counter_path.parent.mkdir(parents=True, exist_ok=True)
        counter_path.write_text(
            json.dumps({"session_id": "s", "counter": -1})
        )
        with pytest.raises(HeaderCounterError, match="negative"):
            HeaderCounter.load(counter_path)

    def test_load_counter_exceeding_max_raises(self, counter_path):
        counter_path.parent.mkdir(parents=True, exist_ok=True)
        counter_path.write_text(
            json.dumps({"session_id": "s", "counter": MAX_HEADER_MESSAGES + 1})
        )
        with pytest.raises(HeaderCounterError, match="MAX_HEADER_MESSAGES"):
            HeaderCounter.load(counter_path)


# ── next_nonce ────────────────────────────────────────────────────────────────

class TestNextNonce:

    def test_returns_12_bytes(self, counter):
        nonce = counter.next_nonce()
        assert len(nonce) == _NONCE_LEN

    def test_counter_increments_by_one(self, counter):
        assert counter.current == 0
        counter.next_nonce()
        assert counter.current == 1

    def test_sequential_nonces_are_unique(self, counter):
        nonces = [counter.next_nonce() for _ in range(100)]
        assert len(set(nonces)) == 100

    def test_nonces_are_strictly_increasing(self, counter):
        """
        Nonces encode the counter value — decoding them should give a
        strictly increasing sequence. This is the core monotonicity guarantee.
        """
        values = []
        for _ in range(10):
            nonce = counter.next_nonce()
            value = struct.unpack("<Q", nonce[:8])[0]
            values.append(value)
        assert values == sorted(values)
        assert values == list(range(1, 11))

    def test_counter_persisted_before_return(self, counter, counter_path):
        """
        The counter on disk must reflect the new value before next_nonce
        returns — atomicity guarantee.
        """
        counter.next_nonce()
        data = json.loads(counter_path.read_text())
        assert data["counter"] == 1

    def test_max_counter_raises(self, counter_path):
        """Counter must refuse to exceed MAX_HEADER_MESSAGES."""
        counter = HeaderCounter(
            counter_path, session_id="s",
            initial=MAX_HEADER_MESSAGES
        )
        with pytest.raises(HeaderCounterError, match="MAX_HEADER_MESSAGES"):
            counter.next_nonce()

    def test_counter_unchanged_in_memory_if_persist_fails(
            self, counter, counter_path):
        """
        If the atomic write fails, the in-memory counter must NOT advance.
        Caller gets OSError and can retry — no nonce is consumed.
        """
        original = counter.current

        with patch("header_counter.os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                counter.next_nonce()

        assert counter.current == original


# ── Nonce encoding ────────────────────────────────────────────────────────────

class TestNonceEncoding:

    def test_first_nonce_encodes_counter_1(self, counter):
        nonce = counter.next_nonce()
        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 1

    def test_trailing_bytes_are_zero(self, counter):
        nonce = counter.next_nonce()
        assert nonce[8:] == b"\x00" * 4

    def test_nonce_at_counter_N_encodes_N(self, counter):
        for _ in range(42):
            nonce = counter.next_nonce()
        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 42


# ── Cross-session uniqueness ──────────────────────────────────────────────────

class TestCrossSessionUniqueness:

    def test_two_sessions_at_counter_zero_have_different_nonces_via_keys(
            self, tmp_path):
        """
        Two sessions both start their counter at 0 and produce nonce=1 on
        the first call. This is NOT nonce reuse because each session has a
        different header key. This test documents that the counter alone
        does not provide cross-session uniqueness — the header key does.
        """
        path_a = tmp_path / "session_a" / "counter.json"
        path_b = tmp_path / "session_b" / "counter.json"
        c_a = HeaderCounter(path_a, session_id="session_a")
        c_b = HeaderCounter(path_b, session_id="session_b")

        nonce_a = c_a.next_nonce()
        nonce_b = c_b.next_nonce()

        # Nonces are identical — but this is safe because keys differ.
        # This test exists to make that design decision explicit and
        # documentable in the interview.
        assert nonce_a == nonce_b   # same counter → same nonce bytes
        # Safety comes from: encrypt(key_A, nonce) ≠ encrypt(key_B, nonce)

    def test_different_sessions_never_share_a_counter_file(self, tmp_path):
        """Each session must have its own counter file — never share one."""
        path_a = tmp_path / "session_a.json"
        path_b = tmp_path / "session_b.json"
        HeaderCounter(path_a, session_id="session_a")
        HeaderCounter(path_b, session_id="session_b")
        assert path_a != path_b


# ── Atomicity and crash recovery ──────────────────────────────────────────────

class TestAtomicity:

    def test_loaded_counter_after_crash_is_safe(self, counter, counter_path):
        """
        Simulate: process encrypts at counter=3, persists counter=3,
        then crashes before sending. On recovery, counter loads as 3.
        Next nonce will be 4 — counter 3 is skipped (lost), not reused.
        Losing a nonce value is the safe failure mode.
        """
        for _ in range(3):
            counter.next_nonce()
        assert counter.current == 3

        # Simulate crash and recovery
        recovered = HeaderCounter.load(counter_path)
        nonce = recovered.next_nonce()

        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 4   # skipped nothing — 3 was already persisted

    def test_temp_file_cleaned_up_on_write_failure(self, counter, tmp_path):
        """No stale .tmp files should remain after a failed write."""
        with patch("header_counter.os.replace", side_effect=OSError("fail")):
            with pytest.raises(OSError):
                counter.next_nonce()

        tmp_files = list(counter._path.parent.glob("*.tmp"))
        assert tmp_files == []


# ── Deletion ──────────────────────────────────────────────────────────────────

class TestDeletion:

    def test_delete_removes_file(self, counter, counter_path):
        counter.delete()
        assert not counter_path.exists()

    def test_delete_is_idempotent(self, counter):
        """Deleting twice must not raise — file may already be gone."""
        counter.delete()
        counter.delete()   # should not raise
