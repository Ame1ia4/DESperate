"""
testing/test_main.py

Tests for main.py — the TCP RPC server.

Covers:
  - handle_unlock_keystore    : missing password, no keystore, wrong/correct password
  - handle_generate_identity_bundle : fresh registration, re-registration correct/wrong
  - handle_client (protocol)  : ID echo, invalid JSON, unknown method, multiple requests
"""
import asyncio
import json
import sys
import unittest.mock
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import main  # noqa: E402 — sys.path must be set first
from core.state_store import StateStore


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def _fake_bundle():
    """Minimal mock IdentityBundle — bypasses slow ML-KEM/ML-DSA key generation."""
    m = unittest.mock.MagicMock()
    m.to_public_bundle.return_value  = {"user_id": "u1", "ik_kem_pub": "aa"}
    m.to_private_bundle.return_value = {"user_id": "u1", "ik_kem_sec": "bb"}
    return m


def _make_writer() -> tuple[unittest.mock.MagicMock, list[dict]]:
    """Return (mock writer, captured responses list)."""
    responses: list[dict] = []

    writer = unittest.mock.MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 9999)
    writer.drain         = unittest.mock.AsyncMock()
    writer.close         = unittest.mock.MagicMock()
    writer.wait_closed   = unittest.mock.AsyncMock()

    def _capture(data: bytes) -> None:
        stripped = data.strip()
        if stripped:
            responses.append(json.loads(stripped))

    writer.write = _capture
    return writer, responses


async def _dispatch(requests: list[dict]) -> list[dict]:
    """Feed a list of request dicts through handle_client, return responses."""
    reader = asyncio.StreamReader()
    for req in requests:
        reader.feed_data(json.dumps(req).encode() + b"\n")
    reader.feed_eof()

    writer, responses = _make_writer()
    await main.handle_client(reader, writer)
    return responses


async def _dispatch_raw(raw_lines: list[bytes]) -> list[dict]:
    """Feed raw byte lines through handle_client — used for invalid JSON tests."""
    reader = asyncio.StreamReader()
    for line in raw_lines:
        reader.feed_data(line)
    reader.feed_eof()

    writer, responses = _make_writer()
    await main.handle_client(reader, writer)
    return responses


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def keystore_dir(tmp_path, monkeypatch) -> Path:
    """Redirect KEYSTORE_DIR to an isolated temp path for each test."""
    d = tmp_path / "keystore"
    monkeypatch.setattr(main, "KEYSTORE_DIR", d)
    return d


@pytest.fixture
def populated_keystore(keystore_dir) -> tuple[Path, str]:
    """Create a real keystore with a known password. Returns (dir, password)."""
    password = "correct-horse-battery"
    store = StateStore.create(keystore_dir, password)
    store.save_state("identity", {"test": "identity-data"})
    return keystore_dir, password


# ── TestUnlockKeystore ────────────────────────────────────────────────────────

class TestUnlockKeystore:

    def test_missing_password_param_returns_error(self, keystore_dir):
        result = _run(main.handle_unlock_keystore({}))
        assert result["success"] is False
        assert "keystore_password" in result["error"]

    def test_empty_password_returns_error(self, keystore_dir):
        result = _run(main.handle_unlock_keystore({"keystore_password": ""}))
        assert result["success"] is False

    def test_no_keystore_returns_register_hint(self, keystore_dir):
        result = _run(main.handle_unlock_keystore({"keystore_password": "anything"}))
        assert result["success"] is False
        assert "Register" in result["error"]

    def test_wrong_password_returns_invalid_password(self, populated_keystore):
        result = _run(main.handle_unlock_keystore({"keystore_password": "wrong"}))
        assert result["success"] is False
        assert "Invalid password" in result["error"]

    def test_correct_password_returns_success(self, populated_keystore):
        _, password = populated_keystore
        result = _run(main.handle_unlock_keystore({"keystore_password": password}))
        assert result == {"success": True}


# ── TestGenerateIdentityBundle ────────────────────────────────────────────────

class TestGenerateIdentityBundle:

    def test_missing_password_returns_error(self, keystore_dir):
        result = _run(main.handle_generate_identity_bundle({}))
        assert "error" in result
        assert "keystore_password" in result["error"]

    def test_empty_password_returns_error(self, keystore_dir):
        result = _run(main.handle_generate_identity_bundle({"keystore_password": ""}))
        assert "error" in result

    def test_fresh_registration_returns_public_bundle(self, keystore_dir):
        with unittest.mock.patch("main._gen_bundle", return_value=_fake_bundle()):
            result = _run(main.handle_generate_identity_bundle({
                "keystore_password": "secret",
                "user_id": "alice",
                "nonce": "ab" * 32,
            }))
        assert "error" not in result
        assert result["user_id"] == "u1"

    def test_fresh_registration_creates_keystore_on_disk(self, keystore_dir):
        with unittest.mock.patch("main._gen_bundle", return_value=_fake_bundle()):
            _run(main.handle_generate_identity_bundle({
                "keystore_password": "secret",
                "user_id": "alice",
            }))
        assert keystore_dir.exists()
        assert (keystore_dir / "salt").exists()

    def test_re_registration_correct_password_succeeds(self, populated_keystore):
        _, password = populated_keystore
        with unittest.mock.patch("main._gen_bundle", return_value=_fake_bundle()):
            result = _run(main.handle_generate_identity_bundle({
                "keystore_password": password,
                "user_id": "alice",
                "nonce": "ab" * 32,
            }))
        assert "error" not in result

    def test_re_registration_wrong_password_rejected(self, populated_keystore):
        with unittest.mock.patch("main._gen_bundle", return_value=_fake_bundle()):
            result = _run(main.handle_generate_identity_bundle({
                "keystore_password": "wrong-password",
                "user_id": "alice",
            }))
        assert "error" in result
        assert "Wrong password" in result["error"]

    def test_re_registration_wrong_password_preserves_keystore(self, populated_keystore):
        """A failed re-registration must not modify the existing keystore on disk."""
        keystore_dir, _ = populated_keystore
        salt_before = (keystore_dir / "salt").read_bytes()

        with unittest.mock.patch("main._gen_bundle", return_value=_fake_bundle()):
            _run(main.handle_generate_identity_bundle({
                "keystore_password": "wrong-password",
                "user_id": "alice",
            }))

        assert (keystore_dir / "salt").read_bytes() == salt_before

    def test_re_registration_correct_password_replaces_salt(self, populated_keystore):
        """
        A new keystore is created after a successful re-registration — the salt
        must change since StateStore generates a fresh one each time.
        """
        keystore_dir, password = populated_keystore
        salt_before = (keystore_dir / "salt").read_bytes()

        with unittest.mock.patch("main._gen_bundle", return_value=_fake_bundle()):
            _run(main.handle_generate_identity_bundle({
                "keystore_password": password,
                "user_id": "alice",
            }))

        assert (keystore_dir / "salt").read_bytes() != salt_before


# ── TestProtocol ──────────────────────────────────────────────────────────────

class TestProtocol:

    def test_request_id_echoed_in_response(self, keystore_dir):
        responses = _run(_dispatch([
            {"id": "req-001", "method": "unlock_keystore", "params": {}},
        ]))
        assert responses[0]["id"] == "req-001"

    def test_null_id_echoed_when_id_absent(self, keystore_dir):
        responses = _run(_dispatch([
            {"method": "unlock_keystore", "params": {}},
        ]))
        assert responses[0]["id"] is None

    def test_unknown_method_returns_error_with_id(self, keystore_dir):
        responses = _run(_dispatch([
            {"id": "req-002", "method": "does_not_exist", "params": {}},
        ]))
        assert "error" in responses[0]
        assert responses[0]["id"] == "req-002"

    def test_invalid_json_returns_error(self, keystore_dir):
        responses = _run(_dispatch_raw([b"not valid json\n"]))
        assert responses[0]["error"] == "Invalid JSON"

    def test_missing_params_field_handled_gracefully(self, keystore_dir):
        """Requests without a params field must not crash the server."""
        responses = _run(_dispatch([
            {"id": "req-003", "method": "unlock_keystore"},
        ]))
        assert "id" in responses[0]
        assert responses[0]["id"] == "req-003"

    def test_multiple_requests_on_same_connection(self, keystore_dir):
        """Each request on a persistent connection gets its own response."""
        responses = _run(_dispatch([
            {"id": "a", "method": "unknown_1", "params": {}},
            {"id": "b", "method": "unknown_2", "params": {}},
            {"id": "c", "method": "unknown_3", "params": {}},
        ]))
        assert len(responses) == 3
        assert [r["id"] for r in responses] == ["a", "b", "c"]

    def test_empty_lines_produce_no_response(self, keystore_dir):
        """Blank lines between requests must be silently skipped."""
        responses = _run(_dispatch_raw([
            b"\n",
            b"\n",
            json.dumps({"id": "x", "method": "no_op", "params": {}}).encode() + b"\n",
        ]))
        assert len(responses) == 1
        assert responses[0]["id"] == "x"

    def test_response_ids_match_request_order(self, keystore_dir):
        """IDs in responses must match the order requests were sent."""
        ids = ["first", "second", "third"]
        responses = _run(_dispatch([
            {"id": i, "method": "unknown", "params": {}} for i in ids
        ]))
        assert [r["id"] for r in responses] == ids
