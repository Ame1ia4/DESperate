"""
tests/test_keys.py

Unit tests for core/keys.py — PQXDH key bundle generation.

Run with: pytest tests/test_keys.py -v
"""

import pytest
from core.keys import (
    KEM_ALG,
    SIG_ALG,
    OPK_COUNT,
    KEMKeypair,
    SigningKeypair,
    X25519Keypair,
    OneTimePrekey,
    SignedPrekey,
    IdentityBundle,
    generate_kem_keypair,
    generate_signing_keypair,
    generate_signed_prekey,
    generate_one_time_prekeys,
    generate_identity_bundle,
    verify_spk_signature,
    replenish_one_time_prekeys,
)


# ── ML-KEM-1024 keypair ──────────────────────────────────────────────────────

class TestKEMKeypair:

    def test_public_key_is_1568_bytes(self):
        """FIPS 203 §7.1: ML-KEM-1024 encapsulation key is 1568 bytes."""
        kp = generate_kem_keypair()
        assert len(kp.public_key) == 1568

    def test_secret_key_is_3168_bytes(self):
        """FIPS 203 §7.1: ML-KEM-1024 decapsulation key is 3168 bytes."""
        kp = generate_kem_keypair()
        assert len(kp.secret_key) == 3168

    def test_two_keypairs_are_different(self):
        """Each call must use a fresh CSPRNG draw — keys must not repeat."""
        kp1 = generate_kem_keypair()
        kp2 = generate_kem_keypair()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key

    def test_public_bytes_returns_public_key(self):
        kp = generate_kem_keypair()
        assert kp.public_bytes() == kp.public_key

    def test_repr_does_not_expose_secret_key(self):
        kp = generate_kem_keypair()
        assert "secret" not in repr(kp).lower()
        assert kp.secret_key.hex() not in repr(kp)


# ── ML-DSA-87 signing keypair ────────────────────────────────────────────────

class TestSigningKeypair:

    def test_public_key_is_2592_bytes(self):
        """FIPS 204 §5: ML-DSA-87 verification key is 2592 bytes."""
        kp = generate_signing_keypair()
        assert len(kp.public_key) == 2592

    def test_secret_key_is_4896_bytes(self):
        """FIPS 204 §5: ML-DSA-87 signing key is 4896 bytes."""
        kp = generate_signing_keypair()
        assert len(kp.secret_key) == 4896

    def test_two_keypairs_are_different(self):
        kp1 = generate_signing_keypair()
        kp2 = generate_signing_keypair()
        assert kp1.public_key != kp2.public_key

    def test_signature_is_4627_bytes(self):
        """FIPS 204 §5: ML-DSA-87 signature is 4627 bytes."""
        kp  = generate_signing_keypair()
        sig = kp.sign(b"test message")
        assert len(sig) == 4627

    def test_sign_is_deterministic_with_same_key(self):
        """
        ML-DSA uses randomised signing by default in liboqs.
        Two signatures over the same message may differ — this is correct
        and both must verify. Test that both verify rather than that they match.
        """
        import oqs
        kp   = generate_signing_keypair()
        msg  = b"same message"
        sig1 = kp.sign(msg)
        sig2 = kp.sign(msg)
        with oqs.Signature(SIG_ALG) as v:
            assert v.verify(msg, sig1, kp.public_key)
            assert v.verify(msg, sig2, kp.public_key)

    def test_signature_verifies_with_correct_key(self):
        import oqs
        kp  = generate_signing_keypair()
        msg = b"hello world"
        sig = kp.sign(msg)
        with oqs.Signature(SIG_ALG) as v:
            assert v.verify(msg, sig, kp.public_key)

    def test_signature_fails_with_wrong_key(self):
        import oqs
        kp1 = generate_signing_keypair()
        kp2 = generate_signing_keypair()
        sig = kp1.sign(b"message")
        with oqs.Signature(SIG_ALG) as v:
            assert not v.verify(b"message", sig, kp2.public_key)

    def test_signature_fails_with_tampered_message(self):
        import oqs
        kp  = generate_signing_keypair()
        sig = kp.sign(b"original message")
        with oqs.Signature(SIG_ALG) as v:
            assert not v.verify(b"tampered message", sig, kp.public_key)

    def test_repr_does_not_expose_secret_key(self):
        kp = generate_signing_keypair()
        assert kp.secret_key.hex() not in repr(kp)


# ── X25519 keypair ───────────────────────────────────────────────────────────

class TestX25519Keypair:

    def test_public_key_is_32_bytes(self):
        kp = X25519Keypair.generate()
        assert len(kp.public_key_bytes) == 32

    def test_private_key_is_32_bytes(self):
        kp = X25519Keypair.generate()
        assert len(kp.private_key_bytes) == 32

    def test_two_keypairs_are_different(self):
        kp1 = X25519Keypair.generate()
        kp2 = X25519Keypair.generate()
        assert kp1.public_key_bytes != kp2.public_key_bytes

    def test_dh_is_symmetric(self):
        """
        Core X25519 property: DH(a_priv, b_pub) == DH(b_priv, a_pub).
        This is the classical leg of PQXDH — both sides must derive the
        same shared secret.
        """
        kp_a = X25519Keypair.generate()
        kp_b = X25519Keypair.generate()
        shared_a = kp_a.dh(kp_b.public_key_bytes)
        shared_b = kp_b.dh(kp_a.public_key_bytes)
        assert shared_a == shared_b

    def test_dh_output_is_32_bytes(self):
        kp_a = X25519Keypair.generate()
        kp_b = X25519Keypair.generate()
        assert len(kp_a.dh(kp_b.public_key_bytes)) == 32

    def test_dh_different_peers_give_different_secrets(self):
        kp_a  = X25519Keypair.generate()
        kp_b1 = X25519Keypair.generate()
        kp_b2 = X25519Keypair.generate()
        assert kp_a.dh(kp_b1.public_key_bytes) != kp_a.dh(kp_b2.public_key_bytes)


# ── Signed prekey ────────────────────────────────────────────────────────────

class TestSignedPrekey:

    @pytest.fixture
    def signing_kp(self):
        return generate_signing_keypair()

    def test_spk_has_correct_id(self, signing_kp):
        spk = generate_signed_prekey(signing_kp, spk_id=7)
        assert spk.spk_id == 7

    def test_spk_signature_is_4627_bytes(self, signing_kp):
        spk = generate_signed_prekey(signing_kp)
        assert len(spk.signature) == 4627

    def test_spk_signature_verifies(self, signing_kp):
        """
        Initiating parties verify this signature before using the SPK.
        A compromised server cannot forge a valid signature without the
        user's ML-DSA-87 secret key.
        """
        spk   = generate_signed_prekey(signing_kp)
        valid = verify_spk_signature(
            spk_pub    = spk.keypair.public_key_bytes,
            signature  = spk.signature,
            ik_sig_pub = signing_kp.public_key,
        )
        assert valid

    def test_tampered_spk_fails_verification(self, signing_kp):
        """Simulates a compromised server substituting a different SPK."""
        spk         = generate_signed_prekey(signing_kp)
        fake_spk    = X25519Keypair.generate()
        valid = verify_spk_signature(
            spk_pub    = fake_spk.public_key_bytes,   # attacker's key
            signature  = spk.signature,               # original signature
            ik_sig_pub = signing_kp.public_key,
        )
        assert not valid

    def test_wrong_signing_key_fails_verification(self, signing_kp):
        """Signature from one identity key must not verify under another."""
        spk          = generate_signed_prekey(signing_kp)
        attacker_kp  = generate_signing_keypair()
        valid = verify_spk_signature(
            spk_pub    = spk.keypair.public_key_bytes,
            signature  = spk.signature,
            ik_sig_pub = attacker_kp.public_key,      # wrong identity key
        )
        assert not valid

    def test_two_spks_have_different_public_keys(self, signing_kp):
        spk1 = generate_signed_prekey(signing_kp, spk_id=1)
        spk2 = generate_signed_prekey(signing_kp, spk_id=2)
        assert spk1.keypair.public_key_bytes != spk2.keypair.public_key_bytes


# ── One-time prekeys ─────────────────────────────────────────────────────────

class TestOneTimePrekeys:

    def test_generates_correct_count(self):
        opks = generate_one_time_prekeys(count=5)
        assert len(opks) == 5

    def test_opk_ids_are_sequential_from_start(self):
        opks = generate_one_time_prekeys(count=5, start_id=10)
        assert [o.opk_id for o in opks] == [10, 11, 12, 13, 14]

    def test_opk_public_keys_are_1568_bytes(self):
        opks = generate_one_time_prekeys(count=3)
        for opk in opks:
            assert len(opk.public_key) == 1568

    def test_opk_secret_keys_are_3168_bytes(self):
        opks = generate_one_time_prekeys(count=3)
        for opk in opks:
            assert len(opk.secret_key) == 3168

    def test_all_opk_public_keys_are_unique(self):
        """Each OPK must be independently generated — no shared entropy."""
        opks = generate_one_time_prekeys(count=OPK_COUNT)
        pubs = [o.public_key for o in opks]
        assert len(set(pubs)) == len(pubs)

    def test_zero_count_returns_empty_list(self):
        assert generate_one_time_prekeys(count=0) == []


# ── Full identity bundle ─────────────────────────────────────────────────────

class TestIdentityBundle:

    @pytest.fixture
    def bundle(self):
        return generate_identity_bundle("alice", opk_count=5)

    def test_bundle_has_correct_user_id(self, bundle):
        assert bundle.user_id == "alice"

    def test_bundle_has_correct_opk_count(self, bundle):
        assert len(bundle.opks) == 5

    def test_public_bundle_contains_no_secret_keys(self, bundle):
        pub = bundle.to_public_bundle()
        serialised = str(pub)
        # None of the secret key hex strings should appear in the public bundle
        assert bundle.ik_kem.secret_key.hex()       not in serialised
        assert bundle.ik_sig.secret_key.hex()       not in serialised
        assert bundle.ik_classical.private_key_bytes.hex() not in serialised
        for opk in bundle.opks:
            assert opk.secret_key.hex() not in serialised

    def test_public_bundle_has_required_fields(self, bundle):
        pub = bundle.to_public_bundle()
        required = {
            "user_id", "ik_kem_pub", "ik_sig_pub", "ik_classical_pub",
            "spk_id", "spk_pub", "spk_sig", "opks",
        }
        assert required.issubset(pub.keys())

    def test_private_bundle_has_all_secret_keys(self, bundle):
        priv = bundle.to_private_bundle()
        assert "ik_kem_sec"       in priv
        assert "ik_sig_sec"       in priv
        assert "ik_classical_sec" in priv
        assert "spk_sec"          in priv
        for opk in priv["opks"]:
            assert "opk_sec" in opk

    def test_public_bundle_spk_signature_verifies(self, bundle):
        """
        End-to-end check: SPK signature in the public bundle must verify
        against the published ML-DSA-87 identity key.
        This is what an initiating client does before using the SPK.
        """
        pub = bundle.to_public_bundle()
        valid = verify_spk_signature(
            spk_pub    = bytes.fromhex(pub["spk_pub"]),
            signature  = bytes.fromhex(pub["spk_sig"]),
            ik_sig_pub = bytes.fromhex(pub["ik_sig_pub"]),
        )
        assert valid

    def test_opk_ids_in_public_bundle_are_unique(self, bundle):
        pub = bundle.to_public_bundle()
        ids = [o["opk_id"] for o in pub["opks"]]
        assert len(set(ids)) == len(ids)

    def test_two_bundles_for_same_user_have_different_keys(self):
        """Registration must always generate fresh key material."""
        b1 = generate_identity_bundle("bob", opk_count=2)
        b2 = generate_identity_bundle("bob", opk_count=2)
        assert b1.ik_kem.public_key != b2.ik_kem.public_key
        assert b1.ik_sig.public_key != b2.ik_sig.public_key


# ── OPK replenishment ────────────────────────────────────────────────────────

class TestReplenishOPKs:

    def test_replenish_fills_to_target(self):
        existing = generate_one_time_prekeys(count=5, start_id=1)
        new_opks = replenish_one_time_prekeys(existing, target_count=20)
        assert len(new_opks) == 15

    def test_replenish_ids_continue_from_highest(self):
        existing = generate_one_time_prekeys(count=5, start_id=1)
        # existing IDs are 1..5
        new_opks = replenish_one_time_prekeys(existing, target_count=8)
        # new IDs should start at 6
        assert new_opks[0].opk_id == 6
        assert new_opks[-1].opk_id == 8

    def test_replenish_with_empty_existing(self):
        new_opks = replenish_one_time_prekeys([], target_count=10)
        assert len(new_opks) == 10
        assert new_opks[0].opk_id == 1

    def test_replenish_when_already_at_target_returns_empty(self):
        existing = generate_one_time_prekeys(count=20, start_id=1)
        new_opks = replenish_one_time_prekeys(existing, target_count=20)
        assert new_opks == []

    def test_replenish_ids_do_not_collide_with_existing(self):
        existing = generate_one_time_prekeys(count=10, start_id=1)
        new_opks = replenish_one_time_prekeys(existing, target_count=15)
        existing_ids = {o.opk_id for o in existing}
        new_ids      = {o.opk_id for o in new_opks}
        assert existing_ids.isdisjoint(new_ids)
