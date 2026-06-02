"""
tests/test_state_store.py

Unit tests for core/state_store.py

Run with: pytest testing/test_state_store.py -v
"""

import json
import os
import time
import pytest
from pathlib import Path
from cryptography.exceptions import InvalidTag

from core.state_store import (
    StateStore,
    SessionMetadata,
    _make_ad,
    _validate_session_id,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def base_dir(tmp_path) -> Path:
    return tmp_path / "state"

@pytest.fixture
def passphrase() -> str:
    return "test_passphrase_123"

@pytest.fixture
def store(base_dir, passphrase) -> StateStore:
    return StateStore.create(base_dir, passphrase)

@pytest.fixture
def session_id() -> str:
    return "session-alice-bob-001"

@pytest.fixture
def sample_state() -> dict:
    return {
        "root_key":       "a" * 64,
        "send_chain_key": "b" * 64,
        "recv_chain_key": "c" * 64,
        "send_msg_num":   0,
        "recv_msg_num":   0,
        "ratchet_pub":    "d" * 64,
    }

@pytest.fixture
def sample_meta(session_id) -> SessionMetadata:
    now = time.time()
    return SessionMetadata(
        session_id    = session_id,
        remote_user   = "bob",
        created_at    = now,
        last_active   = now,
        message_count = 0,
        is_initiator  = True,
        opk_id_used   = 3,
    )


# ── StateStore creation ───────────────────────────────────────────────────────

class TestCreate:

    def test_creates_base_directory(self, base_dir, passphrase):
        StateStore.create(base_dir, passphrase)
        assert base_dir.exists()

    def test_creates_salt_file(self, base_dir, passphrase):
        StateStore.create(base_dir, passphrase)
        assert (base_dir / "salt").exists()

    def test_salt_is_16_bytes(self, base_dir, passphrase):
        StateStore.create(base_dir, passphrase)
        salt = (base_dir / "salt").read_bytes()
        assert len(salt) == 16

    def test_creates_sessions_directory(self, base_dir, passphrase):
        StateStore.create(base_dir, passphrase)
        assert (base_dir / "sessions").exists()

    def test_create_twice_raises(self, base_dir, passphrase):
        StateStore.create(base_dir, passphrase)
        with pytest.raises(FileExistsError):
            StateStore.create(base_dir, passphrase)

    def test_two_stores_have_different_salts(self, tmp_path, passphrase):
        """Each store generates a fresh random salt."""
        s1 = StateStore.create(tmp_path / "s1", passphrase)
        s2 = StateStore.create(tmp_path / "s2", passphrase)
        salt1 = (tmp_path / "s1" / "salt").read_bytes()
        salt2 = (tmp_path / "s2" / "salt").read_bytes()
        assert salt1 != salt2


# ── StateStore loading ────────────────────────────────────────────────────────

class TestLoad:

    def test_load_missing_directory_raises(self, tmp_path, passphrase):
        with pytest.raises(FileNotFoundError):
            StateStore.load(tmp_path / "nonexistent", passphrase)

    def test_load_missing_salt_raises(self, base_dir, passphrase):
        base_dir.mkdir()
        with pytest.raises(FileNotFoundError):
            StateStore.load(base_dir, passphrase)

    def test_load_restores_store(self, base_dir, passphrase,
                                  session_id, sample_state):
        """Create, save, reload, load — must recover the same state."""
        store = StateStore.create(base_dir, passphrase)
        store.save_state(session_id, sample_state)

        reloaded = StateStore.load(base_dir, passphrase)
        recovered = reloaded.load_state(session_id)
        assert recovered == sample_state

    def test_wrong_passphrase_raises_on_decrypt(self, base_dir, passphrase,
                                                  session_id, sample_state):
        """
        A different passphrase derives a different key — decryption must
        fail with InvalidTag, not silently return garbage.
        This is the primary protection against a stolen device.
        """
        store = StateStore.create(base_dir, passphrase)
        store.save_state(session_id, sample_state)

        wrong = StateStore.load(base_dir, "wrong_passphrase")
        with pytest.raises(InvalidTag):
            wrong.load_state(session_id)

    def test_corrupt_salt_raises(self, base_dir, passphrase):
        StateStore.create(base_dir, passphrase)
        (base_dir / "salt").write_bytes(b"\x00" * 8)   # wrong length
        with pytest.raises(ValueError, match="salt"):
            StateStore.load(base_dir, passphrase)


# ── Ratchet state ─────────────────────────────────────────────────────────────

class TestRatchetState:

    def test_save_and_load_roundtrip(self, store, session_id, sample_state):
        store.save_state(session_id, sample_state)
        assert store.load_state(session_id) == sample_state

    def test_state_file_is_not_plaintext(self, store, session_id, sample_state):
        """
        Ratchet state must never be written in plaintext.
        Check that the root_key value does not appear in the file.
        """
        store.save_state(session_id, sample_state)
        path     = store._state_path(session_id)
        raw      = path.read_bytes()
        plaintext = json.dumps(sample_state).encode()
        assert plaintext not in raw

    def test_save_overwrites_previous_state(self, store, session_id, sample_state):
        store.save_state(session_id, sample_state)
        updated = {**sample_state, "send_msg_num": 42}
        store.save_state(session_id, updated)
        assert store.load_state(session_id)["send_msg_num"] == 42

    def test_load_missing_session_raises(self, store):
        with pytest.raises(FileNotFoundError):
            store.load_state("nonexistent-session")

    def test_state_exists_true_after_save(self, store, session_id, sample_state):
        store.save_state(session_id, sample_state)
        assert store.state_exists(session_id) is True

    def test_state_exists_false_before_save(self, store, session_id):
        assert store.state_exists(session_id) is False

    def test_state_file_minimum_size(self, store, session_id):
        """Even empty state must produce a file with nonce + tag overhead."""
        store.save_state(session_id, {})
        path = store._state_path(session_id)
        assert path.stat().st_size >= 12 + 16   # NONCE_LEN + TAG_LEN

    def test_multiple_sessions_stored_independently(self, store, sample_state):
        """Two sessions must not interfere with each other."""
        state_a = {**sample_state, "root_key": "a" * 64}
        state_b = {**sample_state, "root_key": "b" * 64}
        store.save_state("session-a", state_a)
        store.save_state("session-b", state_b)
        assert store.load_state("session-a")["root_key"] == "a" * 64
        assert store.load_state("session-b")["root_key"] == "b" * 64

    def test_tampered_state_file_raises(self, store, session_id, sample_state):
        """
        Any bit flip in the encrypted file must raise InvalidTag.
        A compromised filesystem cannot silently modify ratchet state.
        """
        store.save_state(session_id, sample_state)
        path = store._state_path(session_id)
        raw  = bytearray(path.read_bytes())
        raw[15] ^= 0xFF   # flip a byte in the ciphertext
        path.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            store.load_state(session_id)


# ── Session metadata ──────────────────────────────────────────────────────────

class TestSessionMetadata:

    def test_save_and_load_roundtrip(self, store, session_id, sample_meta):
        store.save_metadata(session_id, sample_meta)
        loaded = store.load_metadata(session_id)
        assert loaded.session_id    == sample_meta.session_id
        assert loaded.remote_user   == sample_meta.remote_user
        assert loaded.message_count == sample_meta.message_count
        assert loaded.is_initiator  == sample_meta.is_initiator
        assert loaded.opk_id_used   == sample_meta.opk_id_used

    def test_metadata_file_is_not_plaintext(self, store, session_id, sample_meta):
        store.save_metadata(session_id, sample_meta)
        path    = store._meta_path(session_id)
        raw     = path.read_bytes()
        assert sample_meta.remote_user.encode() not in raw

    def test_metadata_exists_true_after_save(self, store, session_id, sample_meta):
        store.save_metadata(session_id, sample_meta)
        assert store.metadata_exists(session_id) is True

    def test_metadata_exists_false_before_save(self, store, session_id):
        assert store.metadata_exists(session_id) is False

    def test_load_missing_metadata_raises(self, store):
        with pytest.raises(FileNotFoundError):
            store.load_metadata("nonexistent-session")

    def test_tampered_metadata_raises(self, store, session_id, sample_meta):
        store.save_metadata(session_id, sample_meta)
        path = store._meta_path(session_id)
        raw  = bytearray(path.read_bytes())
        raw[15] ^= 0xFF
        path.write_bytes(bytes(raw))
        with pytest.raises(InvalidTag):
            store.load_metadata(session_id)

    def test_metadata_to_from_dict_roundtrip(self, sample_meta):
        restored = SessionMetadata.from_dict(sample_meta.to_dict())
        assert restored.session_id    == sample_meta.session_id
        assert restored.remote_user   == sample_meta.remote_user
        assert restored.created_at    == sample_meta.created_at
        assert restored.last_active   == sample_meta.last_active
        assert restored.message_count == sample_meta.message_count
        assert restored.is_initiator  == sample_meta.is_initiator
        assert restored.opk_id_used   == sample_meta.opk_id_used

    def test_opk_id_none_roundtrip(self, store, session_id, sample_meta):
        """None opk_id_used must survive serialisation."""
        sample_meta.opk_id_used = None
        store.save_metadata(session_id, sample_meta)
        loaded = store.load_metadata(session_id)
        assert loaded.opk_id_used is None


# ── Associated data binding ───────────────────────────────────────────────────

class TestAssociatedData:

    def test_state_and_meta_have_different_ad(self, session_id):
        """
        State and metadata files for the same session must use different AD.
        A metadata file cannot be decrypted as a state file.
        """
        ad_state = _make_ad(session_id, "state")
        ad_meta  = _make_ad(session_id, "meta")
        assert ad_state != ad_meta

    def test_different_sessions_have_different_ad(self):
        ad_a = _make_ad("session-a", "state")
        ad_b = _make_ad("session-b", "state")
        assert ad_a != ad_b

    def test_state_file_not_decryptable_as_meta(self, store,
                                                  session_id, sample_state):
        """
        Copy a .state file to .meta path and attempt to decrypt as metadata.
        Must fail — AD binds each file to its type.
        """
        store.save_state(session_id, sample_state)
        state_path = store._state_path(session_id)
        meta_path  = store._meta_path(session_id)

        # Copy state blob to meta path
        meta_path.write_bytes(state_path.read_bytes())

        with pytest.raises(InvalidTag):
            store.load_metadata(session_id)

    def test_cross_session_file_rejected(self, store, sample_state):
        """
        Copy session-a's state file to session-b's path.
        Must fail — AD includes session_id.
        """
        store.save_state("session-a", sample_state)
        path_a = store._state_path("session-a")
        path_b = store._state_path("session-b")
        path_b.write_bytes(path_a.read_bytes())

        with pytest.raises(InvalidTag):
            store.load_state("session-b")


# ── Session lifecycle ─────────────────────────────────────────────────────────

class TestSessionLifecycle:

    def test_list_sessions_empty_initially(self, store):
        assert store.list_sessions() == []

    def test_list_sessions_after_save(self, store, session_id, sample_state):
        store.save_state(session_id, sample_state)
        assert session_id in store.list_sessions()

    def test_list_sessions_multiple(self, store, sample_state):
        for sid in ["session-a", "session-b", "session-c"]:
            store.save_state(sid, sample_state)
        sessions = store.list_sessions()
        assert set(sessions) == {"session-a", "session-b", "session-c"}

    def test_delete_session_removes_state_and_meta(self, store, session_id,
                                                     sample_state, sample_meta):
        store.save_state(session_id, sample_state)
        store.save_metadata(session_id, sample_meta)
        store.delete_session(session_id)
        assert not store.state_exists(session_id)
        assert not store.metadata_exists(session_id)

    def test_delete_nonexistent_session_does_not_raise(self, store):
        store.delete_session("nonexistent-session")   # must not raise

    def test_delete_removes_from_list(self, store, session_id, sample_state):
        store.save_state(session_id, sample_state)
        store.delete_session(session_id)
        assert session_id not in store.list_sessions()


# ── Session ID validation ─────────────────────────────────────────────────────

class TestSessionIDValidation:

    def test_empty_session_id_raises(self, store, sample_state):
        with pytest.raises(ValueError, match="empty"):
            store.save_state("", sample_state)

    def test_path_traversal_raises(self, store, sample_state):
        """
        Prevent a crafted session_id from escaping the sessions/ directory.
        Critical: without this check, save_state("../../etc/passwd", ...)
        could overwrite system files.
        """
        with pytest.raises(ValueError):
            store.save_state("../../etc/passwd", sample_state)

    def test_slash_in_session_id_raises(self, store, sample_state):
        with pytest.raises(ValueError):
            store.save_state("session/evil", sample_state)

    def test_dot_prefix_raises(self, store, sample_state):
        with pytest.raises(ValueError):
            store.save_state(".hidden", sample_state)

    def test_valid_session_ids_accepted(self, store, sample_state):
        valid_ids = [
            "session-alice-bob-001",
            "abc123",
            "SESSION_A",
            "a-b-c-d-e-f",
        ]
        for sid in valid_ids:
            store.save_state(sid, sample_state)
            assert store.state_exists(sid)


# ── Header counter persistence ────────────────────────────────────────────────

class TestHeaderCounterPersistence:

    def test_save_and_load_counter(self, store, session_id, sample_state):
        """Counter value survives save/load cycle."""
        store.save_state(session_id, sample_state)
        store.save_counter(session_id, 42)
        assert store.load_counter(session_id) == 42

    def test_load_counter_default_zero(self, store):
        """No state yet — counter defaults to 0 (new session)."""
        assert store.load_counter("brand-new-session") == 0

    def test_save_counter_updates_existing_state(self, store, session_id,
                                                   sample_state):
        """
        save_counter must not overwrite existing ratchet state —
        it updates the header_counter key only.
        """
        store.save_state(session_id, sample_state)
        store.save_counter(session_id, 10)

        state = store.load_state(session_id)
        assert state["root_key"]       == sample_state["root_key"]
        assert state["header_counter"] == 10

    def test_counter_increments_survive_reload(self, store, session_id,
                                                sample_state):
        """
        Simulate a sequence of messages: increment counter, persist,
        reload, verify counter continues from correct position.
        """
        store.save_state(session_id, sample_state)

        from core.header_counter import HeaderCounter
        counter = HeaderCounter(session_id=session_id, initial=0)

        for _ in range(5):
            counter.next_nonce()
            store.save_counter(session_id, counter.current)

        assert counter.current == 5

        # Simulate process restart
        saved_value = store.load_counter(session_id)
        restored    = HeaderCounter(session_id=session_id, initial=saved_value)
        assert restored.current == 5

        # Next nonce must be 6, not 1
        import struct
        nonce   = restored.next_nonce()
        decoded = struct.unpack("<Q", nonce[:8])[0]
        assert decoded == 6

    def test_counter_reset_persisted_as_zero(self, store, session_id,
                                               sample_state):
        """
        After a DH ratchet step, the counter resets to 0.
        The reset must be persisted so the restored counter also starts at 0.
        """
        store.save_state(session_id, sample_state)
        store.save_counter(session_id, 99)
        assert store.load_counter(session_id) == 99

        # DH ratchet step — reset and persist
        store.save_counter(session_id, 0)
        assert store.load_counter(session_id) == 0

    def test_counter_tamper_raises(self, store, session_id, sample_state):
        """
        Tampering with the state file (which contains the counter) must
        raise InvalidTag — counter cannot be silently manipulated.
        """
        store.save_state(session_id, sample_state)
        store.save_counter(session_id, 5)

        path = store._state_path(session_id)
        raw  = bytearray(path.read_bytes())
        raw[15] ^= 0xFF
        path.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            store.load_counter(session_id)
