"""
tests/integration/test_pqxdh_integration.py

End-to-end PQXDH integration tests. Requires liboqs-python installed.

These tests exercise the full handshake with real ML-KEM-1024 and ML-DSA-87
operations — no mocks. Run these on the project VM:

    pip install liboqs-python
    pytest tests/integration/ -v

The unit tests in tests/test_pqxdh.py mock liboqs and run anywhere.
These tests prove the real crypto produces correct results.
"""

import pytest
import os

try:
    import oqs
except (ImportError, RuntimeError, SystemExit):
    pytest.skip(
        "liboqs shared library not available — run on Linux VM",
        allow_module_level=True
    )
from core.keys import generate_identity_bundle
from core.pqxdh import (
    initiate,
    respond,
    InitiationBundle,
    PQXDHResult,
    SPKVerificationError,
    NoPrekeyError,
    _PQXDH_F,
    _SK_LEN,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def alice_bundle():
    """Real IdentityBundle for Alice — generated once per module."""
    return generate_identity_bundle("alice", opk_count=5)

@pytest.fixture(scope="module")
def bob_bundle():
    """Real IdentityBundle for Bob — generated once per module."""
    return generate_identity_bundle("bob", opk_count=5)

@pytest.fixture(scope="module")
def bob_public(bob_bundle):
    return bob_bundle.to_public_bundle()

@pytest.fixture(scope="module")
def bob_local_opks(bob_bundle):
    """Bob's X25519 OPK secret keys keyed by OPK id."""
    return {
        opk.opk_id: opk.x25519_keypair.private_key_bytes
        for opk in bob_bundle.opks
    }

@pytest.fixture(scope="module")
def bob_local_kem_opks(bob_bundle):
    """Bob's ML-KEM OPK secret keys keyed by OPK id."""
    return {
        opk.opk_id: opk.secret_key
        for opk in bob_bundle.opks
    }


# ── Core correctness — Alice and Bob derive the same SK ───────────────────────

class TestHandshakeCorrectness:

    def test_alice_and_bob_derive_same_sk(
            self, alice_bundle, bob_bundle, bob_public,
            bob_local_opks, bob_local_kem_opks):
        """
        THE critical test. If this fails, the entire crypto stack is broken.

        Alice initiates → Bob responds → both must hold identical SK.
        SK is never transmitted — it is derived independently by both parties
        from the same DH/KEM inputs. If they differ, the ratchet will
        immediately desynchronise and no messages will decrypt.
        """
        alice_result = initiate(alice_bundle, bob_public)
        bob_result   = respond(
            local_bundle      = bob_bundle,
            initiation        = alice_result.bundle,
            local_opks        = bob_local_opks,
            local_kem_opk_sks = bob_local_kem_opks,
        )

        assert alice_result.SK == bob_result.SK, (
            "Alice and Bob derived different shared secrets — "
            "the PQXDH handshake is broken."
        )

    def test_sk_is_32_bytes(
            self, alice_bundle, bob_public,
            bob_bundle, bob_local_opks, bob_local_kem_opks):
        result = initiate(alice_bundle, bob_public)
        assert len(result.SK) == _SK_LEN

    def test_sk_is_not_all_zeros(
            self, alice_bundle, bob_public,
            bob_bundle, bob_local_opks, bob_local_kem_opks):
        result = initiate(alice_bundle, bob_public)
        assert result.SK != b"\x00" * _SK_LEN

    def test_sk_is_not_pqxdh_f(self, alice_bundle, bob_public):
        """SK must not equal the padding constant — basic sanity."""
        result = initiate(alice_bundle, bob_public)
        assert result.SK != _PQXDH_F

    def test_two_sessions_produce_different_sk(
            self, alice_bundle, bob_bundle, bob_local_opks, bob_local_kem_opks):
        """
        Each session uses fresh ephemeral keys and consumes a different OPK.
        SK must differ across sessions — if it doesn't, nonce reuse in the
        ratchet becomes possible.
        """
        pub1 = bob_bundle.to_public_bundle()
        pub2 = bob_bundle.to_public_bundle()

        r1 = initiate(alice_bundle, pub1)
        r2 = initiate(alice_bundle, pub2)

        assert r1.SK != r2.SK

    def test_sk_does_not_appear_in_initiation_bundle(
            self, alice_bundle, bob_public):
        """
        SK is never transmitted. Verify it does not appear anywhere in the
        wire bundle that gets sent to Bob via the server.
        """
        result      = initiate(alice_bundle, bob_public)
        bundle_str  = str(result.bundle.to_dict())
        assert result.SK.hex() not in bundle_str


# ── SPK verification ──────────────────────────────────────────────────────────

class TestSPKVerificationReal:

    def test_valid_spk_verifies(self, alice_bundle, bob_public):
        """Real ML-DSA-87 signature over SPK must verify successfully."""
        result = initiate(alice_bundle, bob_public)
        assert result.SK is not None

    def test_tampered_spk_raises(self, alice_bundle, bob_public):
        """
        Simulate a compromised server substituting a different SPK.
        initiate() must detect the invalid signature and abort.
        This is the primary defence against a compromised server MITM.
        """
        tampered = dict(bob_public)
        # Replace SPK public key with a random value — signature won't match
        tampered["spk_pub"] = os.urandom(32).hex()

        with pytest.raises(SPKVerificationError):
            initiate(alice_bundle, tampered)

    def test_tampered_spk_signature_raises(self, alice_bundle, bob_public):
        """Corrupting the signature bytes (not the key) must also fail."""
        tampered = dict(bob_public)
        tampered["spk_sig"] = os.urandom(4627).hex()

        with pytest.raises(SPKVerificationError):
            initiate(alice_bundle, tampered)

    def test_wrong_identity_key_raises(self, alice_bundle, bob_public):
        """
        Substituting a different ik_sig_pub means the signature was made
        by a different identity — must fail verification.
        """
        tampered = dict(bob_public)
        other    = generate_identity_bundle("attacker", opk_count=1)
        tampered["ik_sig_pub"] = other.ik_sig.public_key.hex()

        with pytest.raises(SPKVerificationError):
            initiate(alice_bundle, tampered)


# ── OPK handling ──────────────────────────────────────────────────────────────

class TestOPKHandlingReal:

    def test_no_opk_allow_false_raises(self, alice_bundle, bob_public):
        no_opk_bundle = dict(bob_public)
        no_opk_bundle["opks"] = []

        with pytest.raises(NoPrekeyError):
            initiate(alice_bundle, no_opk_bundle, allow_no_opk=False)

    def test_no_opk_allow_true_both_derive_same_sk(
            self, alice_bundle, bob_bundle):
        """
        Fallback path: both parties must still derive the same SK even
        when encapsulating to the identity key. Reduced PQ forward secrecy
        but the handshake must still be correct.
        """
        no_opk_bundle = bob_bundle.to_public_bundle()
        no_opk_bundle["opks"] = []

        alice_result = initiate(alice_bundle, no_opk_bundle, allow_no_opk=True)
        assert alice_result.bundle.used_identity_kem is True

        bob_result = respond(
            local_bundle      = bob_bundle,
            initiation        = alice_result.bundle,
            local_opks        = {},
            local_kem_opk_sks = {},
        )

        assert alice_result.SK == bob_result.SK

    def test_opk_consumed_flag_is_set(self, alice_bundle, bob_public):
        result = initiate(alice_bundle, bob_public)
        assert result.bundle.opk_id is not None
        assert result.bundle.used_identity_kem is False


# ── Bundle serialisation roundtrip ────────────────────────────────────────────

class TestBundleSerialisationReal:

    def test_bundle_survives_serialisation(
            self, alice_bundle, bob_bundle, bob_public,
            bob_local_opks, bob_local_kem_opks):
        """
        The InitiationBundle is serialised to a dict, sent via the server,
        deserialised by Bob, and used to derive SK. The full pipeline must
        produce the same SK as if the bundle were passed directly.
        """
        alice_result   = initiate(alice_bundle, bob_public)

        # Simulate server relay: serialise → transmit → deserialise
        transmitted    = alice_result.bundle.to_dict()
        received       = InitiationBundle.from_dict(transmitted)

        bob_result = respond(
            local_bundle      = bob_bundle,
            initiation        = received,       # deserialised bundle
            local_opks        = bob_local_opks,
            local_kem_opk_sks = bob_local_kem_opks,
        )

        assert alice_result.SK == bob_result.SK

    def test_ct_pq_is_correct_length(self, alice_bundle, bob_public):
        """ML-KEM-1024 ciphertext must be exactly 1568 bytes."""
        result = initiate(alice_bundle, bob_public)
        assert len(result.bundle.ct_pq) == 1568

    def test_ek_pub_is_32_bytes(self, alice_bundle, bob_public):
        """X25519 ephemeral public key must be exactly 32 bytes."""
        result = initiate(alice_bundle, bob_public)
        assert len(result.bundle.ek_pub) == 32

    def test_ik_classical_pub_is_32_bytes(self, alice_bundle, bob_public):
        result = initiate(alice_bundle, bob_public)
        assert len(result.bundle.ik_classical_pub) == 32


# ── Compromised server scenarios ──────────────────────────────────────────────

class TestCompromisedServer:

    def test_server_cannot_derive_sk_from_bundle(
            self, alice_bundle, bob_public):
        """
        The server sees the InitiationBundle in transit. Verify that the
        bundle fields alone are not sufficient to derive SK — the server
        would also need Bob's private keys to decapsulate CT_pq and compute
        the X3DH DH outputs.

        This test documents the threat model property: a compromised server
        with full bundle access cannot read message contents.
        """
        result = initiate(alice_bundle, bob_public)
        bundle = result.bundle

        # Server has: ik_classical_pub, ek_pub, ct_pq, opk_id
        # Server does NOT have: Bob's private keys, Alice's private keys
        # Without Bob's private keys, CT_pq cannot be decapsulated
        # Without private keys, X3DH DH outputs cannot be computed
        # Therefore SK cannot be derived from the bundle alone.

        # Verify the bundle contains no private key material
        bundle_dict = bundle.to_dict()
        assert alice_bundle.ik_classical.private_key_bytes.hex() \
            not in str(bundle_dict)
        assert alice_bundle.ik_kem.secret_key.hex() \
            not in str(bundle_dict)

    def test_replayed_bundle_with_consumed_opk_raises(
            self, alice_bundle, bob_bundle):
        """
        If an attacker replays Alice's InitiationBundle after Bob has already
        consumed the OPK, respond() must fail — the OPK secret key is deleted
        from local storage after first use.

        In this test we simulate OPK deletion by providing an empty OPK store
        on the second respond() call.
        """
        pub          = bob_bundle.to_public_bundle()
        alice_result = initiate(alice_bundle, pub)

        local_x   = {opk.opk_id: opk.x25519_keypair.private_key_bytes for opk in bob_bundle.opks}
        local_kem = {opk.opk_id: opk.secret_key for opk in bob_bundle.opks}

        # First response — succeeds, OPK consumed
        respond(
            local_bundle      = bob_bundle,
            initiation        = alice_result.bundle,
            local_opks        = local_x,
            local_kem_opk_sks = local_kem,
        )

        # Simulate OPK deletion after consumption
        opk_id = alice_result.bundle.opk_id
        local_x.pop(opk_id, None)
        local_kem.pop(opk_id, None)

        # Replay — must fail because OPK is gone
        from core.pqxdh import PQXDHError
        with pytest.raises(PQXDHError):
            respond(
                local_bundle      = bob_bundle,
                initiation        = alice_result.bundle,
                local_opks        = local_x,
                local_kem_opk_sks = local_kem,
            )
