"""
core/dh_ratchet/dh_ratchet.py

X25519 DiffieHellmanRatchet subclass for python-doubleratchet.

Each DH ratchet step performs standard X25519 key agreement:
  - Both parties independently generate fresh X25519 keypairs each step.
  - _perform_diffie_hellman(own_priv, other_pub) computes the shared secret
    using the local private key and the remote party's public key.
  - The result feeds into the root KDF (KDF_RK) to advance the root chain.

X25519 is symmetric: either party can compute the same shared secret from
each other's public keys without any additional ciphertext transmission.
Public keys are 32 bytes; no extra header fields are required.

References:
  Signal Double Ratchet spec §2:  https://signal.org/docs/specifications/doubleratchet/
  RFC 7748 (X25519):              https://www.rfc-editor.org/rfc/rfc7748
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from doubleratchet import DiffieHellmanRatchet as _BaseDHRatchet


class X25519Ratchet(_BaseDHRatchet):
    """
    Double Ratchet DH step using X25519 key agreement.

    Each ratchet step:
      1. Generate a fresh X25519 keypair (new ratchet key).
      2. Transmit the new public key (32 bytes) in the message header.
      3. Both sender and receiver compute the shared secret independently
         via X25519(own_priv, other_pub).
      4. Feed the shared secret into the root KDF.
    """

    @staticmethod
    def _generate_priv() -> bytes:
        """Generate a fresh 32-byte X25519 private key for a ratchet step."""
        return X25519PrivateKey.generate().private_bytes_raw()

    @staticmethod
    def _derive_pub(priv: bytes) -> bytes:
        """Derive the 32-byte X25519 public key from a private key."""
        return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()

    @classmethod
    def _generate_key_pair(cls) -> tuple:
        """Generate a (pub, priv) keypair — used by tests and legacy callers."""
        priv = cls._generate_priv()
        return cls._derive_pub(priv), priv

    @staticmethod
    def _perform_diffie_hellman(
        own_priv:  bytes,
        other_pub: bytes,
    ) -> bytes:
        """
        Perform one X25519 ratchet step.

        Parameters
        ----------
        own_priv  : 32-byte X25519 private key
        other_pub : 32-byte X25519 public key from the remote party's header

        Returns
        -------
        bytes : 32-byte shared secret fed into the root KDF
        """
        priv = X25519PrivateKey.from_private_bytes(own_priv)
        pub  = X25519PublicKey.from_public_bytes(other_pub)
        return priv.exchange(pub)
