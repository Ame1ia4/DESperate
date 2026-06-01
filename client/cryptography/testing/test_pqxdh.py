"""
tests/test_pqxdh.py

Unit tests for core/pqxdh.py — PQXDH session initiation.

These tests use mocked ML-KEM and X25519 primitives so they run without
liboqs installed. Integration tests (with real liboqs) live in
tests/integration/test_pqxdh_integration.py.

Run with: pytest tests/test_pqxdh.py -v
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import dataclass, field
from typing import Optional

# ── Minimal stubs so tests run without liboqs ─────────────────────────────────

# Stub IdentityBundle and related types so we don't need the full keys.py
@dataclass
class _StubX25519Keypair:
    _secret: bytes
    _public: bytes

    @classmethod
    def generate(cls):
        sec = os.urandom(32)
        pub = os.urandom(32)
        return cls(sec, pub)

    @property
    def public_key_bytes(self): return self._public
    @property
    def private_key_bytes(self): return self._secret

    def dh(self, peer_pub: bytes) -> bytes:
        # Deterministic stub: XOR secret with peer pub — symmetric
        return bytes(a ^ b for a, b in zip(self._secret, peer_pub))


@dataclass
class _StubKEMKeypair:
    public_key: bytes
    secret_key: bytes


@dataclass
class _StubSigningKeypair:
    public_key:         bytes
    secret_key:         bytes
    ed25519_secret_key: bytes = field(default_factory=lambda: b"\x00" * 32)

    def sign(self, msg: bytes) -> bytes:
        return b"\xab" * 4691   # stub hybrid signature (64 + 4627 bytes)


@dataclass
class _StubSPK:
    spk_id: int
    keypair: _StubX25519Keypair
    signature: bytes


@dataclass
class _StubIdentityBundle:
    user_id: str
    ik_kem: _StubKEMKeypair
    ik_sig: _StubSigningKeypair
    ik_classical: _StubX25519Keypair
    spk: _StubSPK
    x25519_opks: list = None
    kem_opks: list = None

    def __post_init__(self):
        if self.x25519_opks is None:
            self.x25519_opks = []
        if self.kem_opks is None:
            self.kem_opks = []

    def to_public_bundle(self) -> dict:
        x25519_opks = [
            {"opk_id": i, "opk_pub": os.urandom(32).hex()}
            for i in range(3)
        ]
        kem_opks = [
            {"opk_id": i, "opk_pub": os.urandom(1568).hex()}
            for i in range(3)
        ]
        return {
            "user_id":          self.user_id,
            "ik_kem_pub":       self.ik_kem.public_key.hex(),
            "ik_sig_pub":       self.ik_sig.public_key.hex(),
            "ik_classical_pub": self.ik_classical.public_key_bytes.hex(),
            "spk_id":           self.spk.spk_id,
            "spk_pub":          self.spk.keypair.public_key_bytes.hex(),
            "spk_sig":          self.spk.signature.hex(),
            "opks_x25519":      x25519_opks,
            "opks_kem":         kem_opks,
        }


def _make_bundle(user_id: str = "bob") -> _StubIdentityBundle:
    return _StubIdentityBundle(
        user_id      = user_id,
        ik_kem       = _StubKEMKeypair(os.urandom(1568), os.urandom(3168)),
        ik_sig       = _StubSigningKeypair(os.urandom(2592), os.urandom(4896)),
        ik_classical = _StubX25519Keypair.generate(),
        spk          = _StubSPK(
            spk_id    = 1,
            keypair   = _StubX25519Keypair.generate(),
            signature = b"\xab" * 4627,
        ),
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def alice():
    return _make_bundle("alice")

@pytest.fixture
def bob():
    return _make_bundle("bob")

@pytest.fixture
def bob_public(bob):
    return bob.to_public_bundle()


# ── Import pqxdh with mocked dependencies ─────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_dependencies(monkeypatch):
    """
    Mock oqs, keys, and kdf dependencies so tests run without liboqs.
    Each test that needs specific mock behaviour can override these.
    """
    # Mock verify_spk_signature to always return True by default
    monkeypatch.setattr("core.pqxdh.verify_spk_signature", lambda *a: True)

    # Mock X25519Keypair.generate to return a stub
    monkeypatch.setattr(
        "core.pqxdh.X25519Keypair",
        type("X25519Keypair", (), {"generate": staticmethod(lambda: _StubX25519Keypair.generate())})
    )

    # Mock _kem_encapsulate to return deterministic (ct, ss)
    monkeypatch.setattr(
        "core.pqxdh._kem_encapsulate",
        lambda pub: (b"\xcc" * 1568, b"\xdd" * 32)
    )

    # Mock _kem_decapsulate to return the same ss
    monkeypatch.setattr(
        "core.pqxdh._kem_decapsulate",
        lambda ct, sk: b"\xdd" * 32
    )

    # Mock _x25519_dh to return deterministic output
    monkeypatch.setattr(
        "core.pqxdh._x25519_dh",
        lambda sk, pub: bytes(a ^ b for a, b in zip(sk[:32], pub[:32]))
    )

    # Mock hkdf_derive to return deterministic 32-byte output
    monkeypatch.setattr(
        "core.pqxdh.hkdf_derive",
        lambda ikm, salt, info, length=32: bytes(
            (sum(ikm[i % len(ikm)] for i in range(j, j+4)) % 256)
            for j in range(0, length * 4, 4)
        )
    )


# ── InitiationBundle serialisation ───────────────────────────────────────────

class TestInitiationBundle:

    def test_to_dict_contains_required_fields(self):
        from core.pqxdh import InitiationBundle
        b = InitiationBundle(
            ik_classical_pub  = os.urandom(32),
            ek_pub            = os.urandom(32),
            ct_pq             = os.urandom(1568),
            opk_id            = 3,
            used_identity_kem = False,
        )
        d = b.to_dict()
        assert "ik_classical_pub"  in d
        assert "ek_pub"            in d
        assert "ct_pq"             in d
        assert "opk_id"            in d
        assert "used_identity_kem" in d

    def test_roundtrip_serialisation(self):
        from core.pqxdh import InitiationBundle
        original = InitiationBundle(
            ik_classical_pub  = os.urandom(32),
            ek_pub            = os.urandom(32),
            ct_pq             = os.urandom(1568),
            opk_id            = 5,
            used_identity_kem = False,
        )
        restored = InitiationBundle.from_dict(original.to_dict())
        assert restored.ik_classical_pub  == original.ik_classical_pub
        assert restored.ek_pub            == original.ek_pub
        assert restored.ct_pq             == original.ct_pq
        assert restored.opk_id            == original.opk_id
        assert restored.used_identity_kem == original.used_identity_kem

    def test_roundtrip_with_no_opk(self):
        from core.pqxdh import InitiationBundle
        b = InitiationBundle(
            ik_classical_pub  = os.urandom(32),
            ek_pub            = os.urandom(32),
            ct_pq             = os.urandom(1568),
            opk_id            = None,
            used_identity_kem = True,
        )
        restored = InitiationBundle.from_dict(b.to_dict())
        assert restored.opk_id            is None
        assert restored.used_identity_kem is True


# ── SPK verification ──────────────────────────────────────────────────────────

class TestSPKVerification:

    def test_invalid_spk_signature_raises(self, alice, bob_public, monkeypatch):
        """
        Simulates a compromised server substituting a different SPK.
        initiate() must abort — never derive SK with an unverified SPK.
        """
        from core.pqxdh import initiate, SPKVerificationError
        monkeypatch.setattr("core.pqxdh.verify_spk_signature", lambda *a: False)

        with pytest.raises(SPKVerificationError):
            initiate(alice, bob_public)

    def test_valid_spk_signature_proceeds(self, alice, bob_public):
        """verify_spk_signature returns True (mocked) — initiation succeeds."""
        from core.pqxdh import initiate
        result = initiate(alice, bob_public)
        assert result.SK is not None
        assert len(result.SK) == 32


# ── OPK handling ──────────────────────────────────────────────────────────────

class TestOPKHandling:

    def test_with_opk_sets_opk_id(self, alice, bob_public):
        """When OPKs are available, opk_id in bundle must be set."""
        from core.pqxdh import initiate
        result = initiate(alice, bob_public)
        assert result.bundle.opk_id is not None

    def test_no_opk_allow_false_raises(self, alice, bob_public):
        """No OPKs + allow_no_opk=False must raise NoPrekeyError."""
        from core.pqxdh import initiate, NoPrekeyError
        bob_public["opks_x25519"] = []
        bob_public["opks_kem"] = []
        with pytest.raises(NoPrekeyError):
            initiate(alice, bob_public, allow_no_opk=False)

    def test_no_opk_allow_true_uses_identity_key(self, alice, bob_public):
        """
        No OPKs + allow_no_opk=True must fall back to identity key.
        KNOWN LIMITATION: reduced PQ forward secrecy — document in design doc.
        """
        from core.pqxdh import initiate
        bob_public["opks_x25519"] = []
        bob_public["opks_kem"] = []
        result = initiate(alice, bob_public, allow_no_opk=True)
        assert result.bundle.used_identity_kem is True
        assert result.bundle.opk_id is None
        assert len(result.SK) == 32

    def test_with_opk_used_identity_kem_is_false(self, alice, bob_public):
        from core.pqxdh import initiate
        result = initiate(alice, bob_public)
        assert result.bundle.used_identity_kem is False

    def test_missing_opks_x25519_raises_malformed(self, alice, bob_public):
        """
        Bundle missing opks_x25519 must raise MalformedBundleError — not
        fall back silently to the old combined format.
        """
        from core.pqxdh import initiate, MalformedBundleError
        del bob_public["opks_x25519"]
        with pytest.raises(MalformedBundleError):
            initiate(alice, bob_public)

    def test_missing_opks_kem_raises_malformed(self, alice, bob_public):
        """Bundle missing opks_kem must raise MalformedBundleError."""
        from core.pqxdh import initiate, MalformedBundleError
        del bob_public["opks_kem"]
        with pytest.raises(MalformedBundleError):
            initiate(alice, bob_public)

    def test_mismatched_opk_list_lengths_raise_malformed(self, alice, bob_public):
        """
        opks_x25519 and opks_kem with different lengths must raise
        MalformedBundleError — not silently truncate via zip().
        """
        from core.pqxdh import initiate, MalformedBundleError
        bob_public["opks_kem"] = bob_public["opks_kem"][:1]  # truncate to 1
        with pytest.raises(MalformedBundleError):
            initiate(alice, bob_public)

    def test_combined_opks_format_raises_malformed(self, alice, bob_public):
        """
        Old combined 'opks' format (opk_pub + opk_kem_pub in one list) is no
        longer supported. Must raise MalformedBundleError, not succeed silently.
        """
        from core.pqxdh import initiate, MalformedBundleError
        del bob_public["opks_x25519"]
        del bob_public["opks_kem"]
        bob_public["opks"] = [
            {"opk_id": 0, "opk_pub": os.urandom(32).hex(), "opk_kem_pub": os.urandom(1568).hex()}
        ]
        with pytest.raises(MalformedBundleError):
            initiate(alice, bob_public)


# ── Shared secret properties ──────────────────────────────────────────────────

class TestSharedSecret:

    def test_sk_is_32_bytes(self, alice, bob_public):
        from core.pqxdh import initiate
        result = initiate(alice, bob_public)
        assert len(result.SK) == 32

    def test_sk_is_not_all_zeros(self, alice, bob_public):
        """SK must not be trivially zero — basic sanity check."""
        from core.pqxdh import initiate
        result = initiate(alice, bob_public)
        assert result.SK != b"\x00" * 32

    def test_different_sessions_produce_different_sk(self, alice, bob_public,
                                                      monkeypatch):
        """
        Each session generates fresh ephemeral keys and OPKs — SK must
        differ across sessions even between the same pair of users.
        """
        from core.pqxdh import initiate

        call_count = [0]
        def unique_encapsulate(pub):
            call_count[0] += 1
            return (
                bytes([call_count[0]] * 1568),
                bytes([call_count[0]] * 32),
            )
        monkeypatch.setattr("core.pqxdh._kem_encapsulate", unique_encapsulate)

        r1 = initiate(alice, bob_public)
        r2 = initiate(alice, bob_public)
        assert r1.SK != r2.SK

    def test_initiator_bundle_does_not_contain_sk(self, alice, bob_public):
        """
        SK must never appear in the InitiationBundle — it is never sent
        to the server or the responder directly.
        """
        from core.pqxdh import initiate
        result = initiate(alice, bob_public)
        bundle_bytes = str(result.bundle.to_dict()).encode()
        assert result.SK not in bundle_bytes


# ── Responder ─────────────────────────────────────────────────────────────────

class TestResponder:

    def _make_local_opks(self, bob_public: dict) -> tuple[dict, dict]:
        """Build fake local OPK stores matching the split bundle format."""
        local_x_opks   = {}
        local_kem_opks = {}
        for opk in bob_public.get("opks_x25519", []):
            local_x_opks[opk["opk_id"]] = os.urandom(32)
        for opk in bob_public.get("opks_kem", []):
            local_kem_opks[opk["opk_id"]] = os.urandom(3168)
        return local_x_opks, local_kem_opks

    def test_responder_sk_is_32_bytes(self, alice, bob, bob_public):
        from core.pqxdh import initiate, respond, InitiationBundle

        init_result  = initiate(alice, bob_public)
        local_x, local_kem = self._make_local_opks(bob_public)

        resp_result = respond(
            local_bundle      = bob,
            initiation        = init_result.bundle,
            local_x25519_opks = local_x,
            local_kem_opks    = local_kem,
        )
        assert len(resp_result.SK) == 32

    def test_responder_bundle_is_none(self, alice, bob, bob_public):
        """Responder does not send a bundle back."""
        from core.pqxdh import initiate, respond

        init_result = initiate(alice, bob_public)
        local_x, local_kem = self._make_local_opks(bob_public)

        resp_result = respond(
            local_bundle      = bob,
            initiation        = init_result.bundle,
            local_x25519_opks = local_x,
            local_kem_opks    = local_kem,
        )
        assert resp_result.bundle is None

    def test_missing_opk_raises(self, alice, bob, bob_public):
        """
        If the OPK referenced in the bundle is not in local storage,
        respond() must raise — not silently derive a wrong SK.
        """
        from core.pqxdh import initiate, respond, PQXDHError

        init_result = initiate(alice, bob_public)
        # Empty OPK stores — OPK referenced in bundle not found
        with pytest.raises(PQXDHError, match="not found"):
            respond(
                local_bundle      = bob,
                initiation        = init_result.bundle,
                local_x25519_opks = {},
                local_kem_opks    = {},
            )

    def test_identity_kem_fallback_responds_correctly(
            self, alice, bob, bob_public, monkeypatch):
        """
        When used_identity_kem=True, responder uses local ik_kem secret key.
        Must succeed without any OPKs in local store.
        """
        from core.pqxdh import initiate, respond

        bob_public["opks_x25519"] = []
        bob_public["opks_kem"] = []
        init_result = initiate(alice, bob_public, allow_no_opk=True)
        assert init_result.bundle.used_identity_kem is True

        resp_result = respond(
            local_bundle      = bob,
            initiation        = init_result.bundle,
            local_x25519_opks = {},
            local_kem_opks    = {},
        )
        assert len(resp_result.SK) == 32


# ── IKM construction ──────────────────────────────────────────────────────────

class TestIKMConstruction:

    def test_f_prefix_is_32_xff_bytes(self):
        """
        PQXDH spec §3.3: IKM starts with 32 bytes of 0xFF.
        Prevents cross-protocol confusion.
        """
        from core.pqxdh import _PQXDH_F
        assert _PQXDH_F == b"\xff" * 32
        assert len(_PQXDH_F) == 32

    def test_hkdf_receives_nonzero_ikm(self, alice, bob_public, monkeypatch):
        """
        The IKM passed to HKDF must not be all zeros — verifies that DH
        outputs and SS_pq are actually contributing to the derivation.
        """
        from core.pqxdh import initiate

        captured = {}
        def capture_hkdf(ikm, salt, info, length=32):
            captured["ikm"] = ikm
            return os.urandom(32)
        monkeypatch.setattr("core.pqxdh.hkdf_derive", capture_hkdf)

        initiate(alice, bob_public)
        assert captured["ikm"] != b"\x00" * len(captured["ikm"])

    def test_hkdf_receives_f_prefix(self, alice, bob_public, monkeypatch):
        """IKM must start with _PQXDH_F."""
        from core.pqxdh import initiate, _PQXDH_F

        captured = {}
        def capture_hkdf(ikm, salt, info, length=32):
            captured["ikm"] = ikm
            return os.urandom(32)
        monkeypatch.setattr("core.pqxdh.hkdf_derive", capture_hkdf)

        initiate(alice, bob_public)
        assert captured["ikm"][:32] == _PQXDH_F

    def test_hkdf_uses_pqxdh_info_string(self, alice, bob_public, monkeypatch):
        """INFO_PQXDH_SK must be passed as the HKDF info string."""
        from core.pqxdh import initiate
        from core.kdf import INFO_PQXDH_SK

        captured = {}
        def capture_hkdf(ikm, salt, info, length=32):
            captured["info"] = info
            return os.urandom(32)
        monkeypatch.setattr("core.pqxdh.hkdf_derive", capture_hkdf)

        initiate(alice, bob_public)
        assert captured["info"] == INFO_PQXDH_SK

    def test_hkdf_salt_is_zero_string(self, alice, bob_public, monkeypatch):
        """PQXDH spec §3.3: HKDF salt is a 32-byte zero string."""
        from core.pqxdh import initiate

        captured = {}
        def capture_hkdf(ikm, salt, info, length=32):
            captured["salt"] = salt
            return os.urandom(32)
        monkeypatch.setattr("core.pqxdh.hkdf_derive", capture_hkdf)

        initiate(alice, bob_public)
        assert captured["salt"] == b"\x00" * 32
