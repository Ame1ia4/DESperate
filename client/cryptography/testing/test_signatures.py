"""
tests/test_signatures.py

Unit tests for core/signatures.py
Hybrid Ed25519 + ML-DSA-87 explicit message signing over ciphertext.

Run with: pytest tests/test_signatures.py -v
"""

import struct
import pytest

from core.keys import (
    generate_signing_keypair,
    HYBRID_PUBLIC_KEY_LEN,
    HYBRID_SIGNATURE_LEN,
    ED25519_SIGNATURE_LEN,
)
from core.signatures import (
    SignedCiphertext,
    SignatureVerificationError,
    MalformedSignedCiphertextError,
    HYBRID_SIGNATURE_LEN as SIG_SIGS_HYBRID_LEN,
    sign_ciphertext,
    verify_ciphertext,
    verify_and_extract,
    build_sig_input,
    _lp,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def keypair():
    """One hybrid keypair for the whole module — generation is slow."""
    return generate_signing_keypair()


@pytest.fixture(scope="module")
def keypair_b():
    """A second keypair to test wrong-key rejection."""
    return generate_signing_keypair()


@pytest.fixture
def ciphertext():
    return b"\xAB" * 60   # fake AEAD output (reuse_guard||nonce||ct||tag)


@pytest.fixture
def aad():
    """Length-prefixed associated data — same pattern as aead.py tests."""
    sender    = b"alice"
    recipient = b"bob"
    return struct.pack("!H", len(sender)) + sender + struct.pack("!H", len(recipient)) + recipient


@pytest.fixture
def sender_id():
    return b"alice"


@pytest.fixture
def recipient_id():
    return b"bob"


@pytest.fixture
def message_index():
    return 42


@pytest.fixture
def signed(keypair, ciphertext, aad, sender_id, recipient_id, message_index):
    return sign_ciphertext(keypair, ciphertext, aad, sender_id, recipient_id, message_index)


# ── _lp length-prefix helper ──────────────────────────────────────────────────

class TestLengthPrefix:

    def test_empty_field(self):
        assert _lp(b"") == b"\x00\x00"

    def test_single_byte(self):
        assert _lp(b"\xFF") == b"\x00\x01\xFF"

    def test_length_prefix_is_big_endian(self):
        data = b"hello"
        result = _lp(data)
        (length,) = struct.unpack("!H", result[:2])
        assert length == len(data)
        assert result[2:] == data

    def test_prevents_concatenation_ambiguity(self):
        """
        The whole point of LP: LP(a)||LP(b) must be distinct from
        LP(a')||LP(b') whenever (a,b) != (a',b'), even if a||b == a'||b'.
        """
        assert _lp(b"alice") + _lp(b"bob") != _lp(b"aliceb") + _lp(b"ob")

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="too long"):
            _lp(b"x" * 65536)


# ── build_sig_input ───────────────────────────────────────────────────────────

class TestBuildSigInput:

    def test_returns_bytes(self, ciphertext, aad, sender_id, recipient_id, message_index):
        result = build_sig_input(ciphertext, aad, sender_id, recipient_id, message_index)
        assert isinstance(result, bytes)

    def test_message_index_encoded_little_endian(
            self, ciphertext, aad, sender_id, recipient_id):
        result = build_sig_input(ciphertext, aad, sender_id, recipient_id, 1)
        assert result[-8:] == struct.pack("<Q", 1)

    def test_different_ciphertext_gives_different_input(
            self, aad, sender_id, recipient_id, message_index):
        a = build_sig_input(b"ct1", aad, sender_id, recipient_id, message_index)
        b = build_sig_input(b"ct2", aad, sender_id, recipient_id, message_index)
        assert a != b

    def test_different_aad_gives_different_input(
            self, ciphertext, sender_id, recipient_id, message_index):
        a = build_sig_input(ciphertext, b"aad1", sender_id, recipient_id, message_index)
        b = build_sig_input(ciphertext, b"aad2", sender_id, recipient_id, message_index)
        assert a != b

    def test_different_sender_gives_different_input(
            self, ciphertext, aad, recipient_id, message_index):
        a = build_sig_input(ciphertext, aad, b"alice", recipient_id, message_index)
        b = build_sig_input(ciphertext, aad, b"eve",   recipient_id, message_index)
        assert a != b

    def test_different_recipient_gives_different_input(
            self, ciphertext, aad, sender_id, message_index):
        a = build_sig_input(ciphertext, aad, sender_id, b"bob",   message_index)
        b = build_sig_input(ciphertext, aad, sender_id, b"carol", message_index)
        assert a != b

    def test_different_message_index_gives_different_input(
            self, ciphertext, aad, sender_id, recipient_id):
        a = build_sig_input(ciphertext, aad, sender_id, recipient_id, 0)
        b = build_sig_input(ciphertext, aad, sender_id, recipient_id, 1)
        assert a != b

    def test_sender_recipient_swap_gives_different_input(
            self, ciphertext, aad, message_index):
        """
        Swapping sender and recipient must produce different sig_input.
        Prevents a server reflecting alice→bob back as bob→alice.
        """
        forward  = build_sig_input(ciphertext, aad, b"alice", b"bob",   message_index)
        reversed = build_sig_input(ciphertext, aad, b"bob",   b"alice", message_index)
        assert forward != reversed

    def test_invalid_message_index_raises(self, ciphertext, aad, sender_id, recipient_id):
        with pytest.raises(ValueError, match="uint64"):
            build_sig_input(ciphertext, aad, sender_id, recipient_id, -1)

    def test_large_message_index_boundary(self, ciphertext, aad, sender_id, recipient_id):
        result = build_sig_input(ciphertext, aad, sender_id, recipient_id, 2**64 - 1)
        assert result[-8:] == struct.pack("<Q", 2**64 - 1)


# ── sign_ciphertext ───────────────────────────────────────────────────────────

class TestSignCiphertext:

    def test_returns_signed_ciphertext(self, signed):
        assert isinstance(signed, SignedCiphertext)

    def test_signature_is_4691_bytes(self, signed):
        assert len(signed.signature) == HYBRID_SIGNATURE_LEN  # 4691

    def test_ciphertext_preserved(self, signed, ciphertext):
        assert signed.ciphertext == ciphertext

    def test_sender_id_preserved(self, signed, sender_id):
        assert signed.sender_id == sender_id

    def test_recipient_id_preserved(self, signed, recipient_id):
        assert signed.recipient_id == recipient_id

    def test_message_index_preserved(self, signed, message_index):
        assert signed.message_index == message_index

    def test_ed25519_component_is_64_bytes(self, signed):
        assert len(signed.signature[:ED25519_SIGNATURE_LEN]) == 64

    def test_dsa_component_is_4627_bytes(self, signed):
        assert len(signed.signature[ED25519_SIGNATURE_LEN:]) == 4627


# ── verify_ciphertext ─────────────────────────────────────────────────────────

class TestVerifyCiphertext:

    def test_valid_signature_does_not_raise(self, signed, aad, keypair):
        verify_ciphertext(signed, aad, keypair.public_key)

    def test_wrong_key_raises(self, signed, aad, keypair_b):
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(signed, aad, keypair_b.public_key)

    def test_wrong_aad_raises(self, signed, keypair):
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(signed, b"wrong_aad", keypair.public_key)

    def test_tampered_ciphertext_raises(self, signed, aad, keypair):
        """
        Flipping a bit in the ciphertext invalidates sig_input and therefore
        the signature, before the AEAD tag is ever checked.
        """
        tampered = SignedCiphertext(
            ciphertext    = bytes([signed.ciphertext[0] ^ 0xFF]) + signed.ciphertext[1:],
            signature     = signed.signature,
            sender_id     = signed.sender_id,
            recipient_id  = signed.recipient_id,
            message_index = signed.message_index,
        )
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(tampered, aad, keypair.public_key)

    def test_tampered_sender_id_raises(self, signed, aad, keypair):
        tampered = SignedCiphertext(
            ciphertext    = signed.ciphertext,
            signature     = signed.signature,
            sender_id     = b"eve",   # attacker claims to be eve
            recipient_id  = signed.recipient_id,
            message_index = signed.message_index,
        )
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(tampered, aad, keypair.public_key)

    def test_tampered_recipient_id_raises(self, signed, aad, keypair):
        tampered = SignedCiphertext(
            ciphertext    = signed.ciphertext,
            signature     = signed.signature,
            sender_id     = signed.sender_id,
            recipient_id  = b"carol",
            message_index = signed.message_index,
        )
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(tampered, aad, keypair.public_key)

    def test_tampered_message_index_raises(self, signed, aad, keypair):
        tampered = SignedCiphertext(
            ciphertext    = signed.ciphertext,
            signature     = signed.signature,
            sender_id     = signed.sender_id,
            recipient_id  = signed.recipient_id,
            message_index = signed.message_index + 1,
        )
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(tampered, aad, keypair.public_key)

    def test_wrong_public_key_length_raises(self, signed, aad):
        with pytest.raises(MalformedSignedCiphertextError):
            verify_ciphertext(signed, aad, b"\x00" * (HYBRID_PUBLIC_KEY_LEN - 1))

    def test_reflection_attack_rejected(self, keypair, aad):
        """
        A server cannot replay alice→bob as bob→alice.
        The sender/recipient swap changes sig_input, invalidating the signature.
        """
        ct = b"\xAB" * 60
        forward = sign_ciphertext(keypair, ct, aad, b"alice", b"bob", 0)

        reflected = SignedCiphertext(
            ciphertext    = forward.ciphertext,
            signature     = forward.signature,
            sender_id     = b"bob",    # swapped
            recipient_id  = b"alice",  # swapped
            message_index = forward.message_index,
        )
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(reflected, aad, keypair.public_key)


# ── TOFU pinning ──────────────────────────────────────────────────────────────

class TestTOFUPinning:

    def test_correct_pinned_key_passes(self, signed, aad, keypair):
        verify_ciphertext(
            signed,
            aad,
            keypair.public_key,
            expected_pub = keypair.public_key,
        )

    def test_wrong_pinned_key_raises(self, signed, aad, keypair, keypair_b):
        """
        TOFU mismatch must raise SignatureVerificationError — same error as
        a bad signature, to prevent oracle attacks distinguishing the two.
        """
        with pytest.raises(SignatureVerificationError):
            verify_ciphertext(
                signed,
                aad,
                keypair.public_key,
                expected_pub = keypair_b.public_key,
            )

    def test_tofu_mismatch_error_message_matches_bad_sig(
            self, signed, aad, keypair, keypair_b):
        """
        Oracle prevention: the error message must be identical whether the
        failure is a TOFU mismatch or a bad signature.
        """
        try:
            verify_ciphertext(signed, aad, keypair_b.public_key)
        except SignatureVerificationError as bad_sig_err:
            pass

        try:
            verify_ciphertext(
                signed, aad, keypair.public_key,
                expected_pub = keypair_b.public_key,
            )
        except SignatureVerificationError as tofu_err:
            pass

        assert str(bad_sig_err) == str(tofu_err)

    def test_no_expected_pub_skips_tofu_check(self, signed, aad, keypair):
        """Passing expected_pub=None must not affect a valid verification."""
        verify_ciphertext(signed, aad, keypair.public_key, expected_pub=None)


# ── SignedCiphertext wire format ──────────────────────────────────────────────

class TestSignedCiphertextWireFormat:

    def test_roundtrip(self, signed):
        recovered = SignedCiphertext.from_bytes(signed.to_bytes())
        assert recovered.ciphertext    == signed.ciphertext
        assert recovered.signature     == signed.signature
        assert recovered.sender_id     == signed.sender_id
        assert recovered.recipient_id  == signed.recipient_id
        assert recovered.message_index == signed.message_index

    def test_to_bytes_contains_signature(self, signed):
        wire = signed.to_bytes()
        assert signed.signature in wire

    def test_to_bytes_contains_ciphertext(self, signed):
        wire = signed.to_bytes()
        assert signed.ciphertext in wire

    def test_truncated_payload_raises(self, signed):
        wire = signed.to_bytes()
        with pytest.raises(MalformedSignedCiphertextError):
            SignedCiphertext.from_bytes(wire[:10])

    def test_empty_payload_raises(self):
        with pytest.raises(MalformedSignedCiphertextError):
            SignedCiphertext.from_bytes(b"")

    def test_wrong_sig_len_field_raises(self, signed):
        """
        Patch the sig_len field to a wrong value — from_bytes must reject it
        rather than silently producing a truncated or over-read signature.
        """
        wire = bytearray(signed.to_bytes())
        # sig_len is after LP(sender_id) + LP(recipient_id) + 8-byte index
        sender_lp_size    = _LEN_PREFIX_SIZE + len(signed.sender_id)
        recipient_lp_size = _LEN_PREFIX_SIZE + len(signed.recipient_id)
        sig_len_offset    = sender_lp_size + recipient_lp_size + 8
        # Write an incorrect sig_len
        struct.pack_into("!H", wire, sig_len_offset, HYBRID_SIGNATURE_LEN - 1)
        with pytest.raises(MalformedSignedCiphertextError):
            SignedCiphertext.from_bytes(bytes(wire))

    def test_empty_ciphertext_in_wire_raises(self, keypair, aad, sender_id, recipient_id):
        """A valid header with no ciphertext bytes must be rejected."""
        # Build a wire payload manually with an empty ciphertext section
        sig = keypair.sign(b"dummy")
        wire = (
            _lp(sender_id)
            + _lp(recipient_id)
            + struct.pack("<Q", 0)
            + struct.pack("!H", HYBRID_SIGNATURE_LEN)
            + sig
            # no ciphertext bytes
        )
        with pytest.raises(MalformedSignedCiphertextError):
            SignedCiphertext.from_bytes(wire)

    def test_wrong_signature_length_in_constructor_raises(
            self, ciphertext, sender_id, recipient_id):
        with pytest.raises(MalformedSignedCiphertextError):
            SignedCiphertext(
                ciphertext    = ciphertext,
                signature     = b"\x00" * (HYBRID_SIGNATURE_LEN - 1),
                sender_id     = sender_id,
                recipient_id  = recipient_id,
                message_index = 0,
            )


# ── verify_and_extract ────────────────────────────────────────────────────────

class TestVerifyAndExtract:

    def test_valid_payload_returns_signed_ciphertext(self, signed, aad, keypair):
        result = verify_and_extract(
            data       = signed.to_bytes(),
            aad        = aad,
            ik_sig_pub = keypair.public_key,
        )
        assert result.ciphertext    == signed.ciphertext
        assert result.sender_id     == signed.sender_id
        assert result.recipient_id  == signed.recipient_id
        assert result.message_index == signed.message_index

    def test_malformed_wire_raises_malformed_error(self, aad, keypair):
        with pytest.raises(MalformedSignedCiphertextError):
            verify_and_extract(b"\x00" * 5, aad, keypair.public_key)

    def test_bad_signature_raises_verification_error(self, signed, keypair_b, aad):
        with pytest.raises(SignatureVerificationError):
            verify_and_extract(
                data       = signed.to_bytes(),
                aad        = aad,
                ik_sig_pub = keypair_b.public_key,
            )

    def test_verify_before_return(self, signed, aad, keypair, keypair_b):
        """
        verify_and_extract must verify before returning — calling it with
        the wrong key must raise before the caller ever sees the ciphertext.
        This enforces the verify-before-decrypt call order contract.
        """
        with pytest.raises(SignatureVerificationError):
            result = verify_and_extract(
                data       = signed.to_bytes(),
                aad        = aad,
                ik_sig_pub = keypair_b.public_key,
            )
            # This line must never be reached
            _ = result.ciphertext
