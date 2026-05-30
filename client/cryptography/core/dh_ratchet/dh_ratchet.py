"""
core/dh_ratchet.py

ML-KEM-1024 DiffieHellmanRatchet subclass for python-doubleratchet.

Replaces the standard X25519 DH ratchet step with ML-KEM-1024 encapsulation,
providing post-quantum forward secrecy on every DH ratchet step.

IMPORTANT DIFFERENCE FROM X25519
  X25519 DH is symmetric: both parties can independently compute the same
  shared secret from each other's public keys. ML-KEM is asymmetric:
    - The initiator ENCAPSULATES to the recipient's public key, producing
      (ciphertext, shared_secret).
    - The recipient DECAPSULATES using their private key + the ciphertext.
  Only one party can initiate each ratchet step. The ciphertext must be
  transmitted in the message header alongside the ratchet public key.

  python-doubleratchet models the DH ratchet as:
    - generate_key_pair() → produces a new ratchet keypair
    - _perform_diffie_hellman(own_priv, other_pub) → produces shared secret

  For ML-KEM, _perform_diffie_hellman is called differently per direction:
    - Sender:   own_priv = None, other_pub = recipient's ML-KEM public key
                → encapsulates, stores ciphertext for header transmission
    - Receiver: own_priv = ML-KEM secret key, other_pub = ciphertext from header
                → decapsulates

  This asymmetry is handled transparently by the session layer, which sets
  up the ratchet correctly for each direction.

References:
  Signal Double Ratchet spec §2:  https://signal.org/docs/specifications/doubleratchet/
  FIPS 203 (ML-KEM-1024):         https://doi.org/10.6028/NIST.FIPS.203
  Signal PQXDH + ML-KEM braid:    https://signal.org/docs/specifications/pqxdh/
"""

from __future__ import annotations

import os
import threading
from typing import Optional, Tuple

import oqs

from doubleratchet import DiffieHellmanRatchet as _BaseDHRatchet
from doubleratchet.types import EncryptedMessage, Header

from core.constants import KEM_ALG, KEM_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN


class MLKEMRatchet(_BaseDHRatchet):
    """
    Double Ratchet DH step using ML-KEM-1024 encapsulation.

    Each ratchet step:
      Sender side:
        1. Generate a fresh ML-KEM-1024 keypair (our new ratchet key)
        2. Encapsulate to the recipient's current ratchet public key
        3. Transmit our new public key + encapsulation ciphertext in header
        4. Feed shared secret into root KDF

      Receiver side:
        1. Receive sender's new public key + ciphertext from header
        2. Decapsulate using our current ratchet private key
        3. Feed shared secret into root KDF
        4. Generate our own new ratchet keypair for the next step
    """

    # ── Required by python-doubleratchet ─────────────────────────────────────

    @staticmethod
    def _generate_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML-KEM-1024 keypair for a ratchet step.

        Returns
        -------
        (public_key, secret_key) — both as raw bytes
          public_key : 1568 bytes — transmitted in message header
          secret_key : 3168 bytes — stored locally, never transmitted
        """
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return public_key, secret_key

    @staticmethod
    def _perform_diffie_hellman(
        own_priv:  Optional[bytes],
        other_pub: bytes,
    ) -> bytes:
        """
        Perform one ML-KEM-1024 ratchet step.

        Because ML-KEM is a KEM not a DH function, the operation is
        directional:

        SENDER (own_priv is None):
          other_pub is the recipient's ML-KEM ratchet public key (1568 bytes).
          Encapsulate to it — returns shared_secret. The ciphertext is stored
          on the instance for inclusion in the next message header.

        RECEIVER (own_priv is set):
          other_pub is the ML-KEM ciphertext from the sender's header
          (1568 bytes). Decapsulate using own_priv — returns shared_secret.

        Parameters
        ----------
        own_priv  : None (sender) or ML-KEM secret key bytes (receiver)
        other_pub : ML-KEM public key (sender) or ciphertext (receiver)

        Returns
        -------
        bytes : 32-byte shared secret fed into the root KDF
        """
        if own_priv is None:
            # Sender path — encapsulate to recipient's ratchet public key
            if len(other_pub) != KEM_PUBLIC_KEY_LEN:
                raise ValueError(
                    f"Sender path expects ML-KEM public key "
                    f"({KEM_PUBLIC_KEY_LEN} bytes), got {len(other_pub)}"
                )
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ciphertext, shared_secret = kem.encap_secret(other_pub)
            # Store ciphertext so session layer can include it in the header.
            # Thread-local so concurrent sessions on different threads can't
            # consume each other's ciphertext.
            MLKEMRatchet._local.pending_ciphertext = ciphertext
            return shared_secret
        else:
            # Receiver path — other_pub is the sender's new ML-KEM public key
            # (used by the library to track ratchet state for future DH steps).
            # The actual ciphertext to decapsulate is stashed in
            # _local.pending_kem_ct by the session layer via push_kem_ct()
            # before decrypt_message() is called, keeping the sender's pub key
            # and kem_ct separated across the library boundary so Header.ratchet_pub
            # stays meaningful for subsequent sender→receiver DH steps.
            if len(other_pub) != KEM_PUBLIC_KEY_LEN:
                raise ValueError(
                    f"Receiver path expects sender's ML-KEM public key "
                    f"({KEM_PUBLIC_KEY_LEN} bytes), got {len(other_pub)}"
                )
            kem_ct = getattr(MLKEMRatchet._local, "pending_kem_ct", None)
            if kem_ct is None:
                raise RuntimeError(
                    "No KEM ciphertext available — push_kem_ct() must be "
                    "called before decrypt_message() on the receiver path."
                )
            MLKEMRatchet._local.pending_kem_ct = None
            if len(kem_ct) != KEM_CIPHERTEXT_LEN:
                raise ValueError(
                    f"Stashed KEM ciphertext has wrong length "
                    f"(expected {KEM_CIPHERTEXT_LEN}, got {len(kem_ct)})"
                )
            with oqs.KeyEncapsulation(KEM_ALG, own_priv) as kem:
                return kem.decap_secret(kem_ct)

    # Thread-local storage for ratchet state that crosses the library boundary.
    # Each thread has its own slots, so concurrent sessions on different threads
    # cannot consume each other's values.
    _local: threading.local = threading.local()

    @classmethod
    def pop_pending_ciphertext(cls) -> bytes:
        """
        Retrieve and clear the ciphertext from the last encapsulation.

        Call this immediately after encrypt() to include the ciphertext
        in the message header. Raises if no ciphertext is pending.
        """
        ct = getattr(cls._local, "pending_ciphertext", None)
        if ct is None:
            raise RuntimeError(
                "No pending ciphertext — was pop_pending_ciphertext() "
                "called without a preceding encapsulation?"
            )
        cls._local.pending_ciphertext = None
        return ct

    @classmethod
    def push_kem_ct(cls, kem_ct: bytes) -> None:
        """
        Stash the ML-KEM ciphertext from the wire header so the receiver path
        of the next _perform_diffie_hellman call on this thread can consume it.

        Must be called on the same thread that will call decrypt_message(),
        immediately before that call. The ciphertext is cleared automatically
        after it is consumed by _perform_diffie_hellman.
        """
        cls._local.pending_kem_ct = kem_ct
