"""
core/dh_ratchet/dh_ratchet.py

MLKEMRatchet — DiffieHellmanRatchet subclass that swaps X25519 for ML-KEM-1024.

The Signal Double Ratchet was designed around X25519, which is symmetric: both
parties can independently compute the same shared secret from each other's
public keys. ML-KEM is asymmetric — one party encapsulates to the other's
public key, producing a ciphertext that the holder of the corresponding
private key can decapsulate. To slot ML-KEM into a DH-shaped interface, we
overload the meaning of `other_pub`:

    SENDER  (own_priv is None):
        other_pub holds the RECIPIENT's ML-KEM-1024 public key (1568 bytes).
        We encapsulate to it, returning the shared secret and stashing the
        resulting ciphertext in `_pending_ciphertext` for the session layer
        to pick up and include in the outgoing message header.

    RECEIVER (own_priv is set):
        other_pub holds the ML-KEM-1024 CIPHERTEXT (1568 bytes) carried in
        the incoming message header. We decapsulate using own_priv,
        returning the shared secret. No ciphertext is produced.

In both directions the returned shared secret is a 32-byte value fed into
the root KDF (see ratchet_kdf.py:RootChainKDF) as the `data` parameter.

`_pending_ciphertext` is a CLASS attribute, not an instance attribute. The
python-doubleratchet library invokes our staticmethods, so we have no
instance to attach state to. This is fine for the current single-session
client but is a soft constraint to be aware of: under concurrent sessions
in one process, the class-level slot would race. The session layer pops
it synchronously immediately after every encapsulation, so as long as
encapsulation and pop happen on the same thread (which they do — the
session is awaited end-to-end), this is safe. Documented in the design
document as a known constraint.

The module-level `oqs` import is named explicitly (`import oqs`) so that
tests can monkey-patch `core.dh_ratchet.dh_ratchet.oqs` to mock out liboqs
in environments where it is not installed.

References
----------
FIPS 203 (ML-KEM-1024):
    https://doi.org/10.6028/NIST.FIPS.203
Signal Double Ratchet spec §3 (DH ratchet):
    https://signal.org/docs/specifications/doubleratchet/
liboqs Python bindings (oqs-python):
    https://github.com/open-quantum-safe/liboqs-python
"""

from __future__ import annotations

from typing import Optional, Tuple

import oqs   # monkey-patchable at core.dh_ratchet.dh_ratchet.oqs

from doubleratchet import DiffieHellmanRatchet as _BaseDHRatchet

from core.constants import (
    KEM_ALG,
    KEM_PUBLIC_KEY_LEN,
    KEM_CIPHERTEXT_LEN,
)


class MLKEMRatchet(_BaseDHRatchet):
    """
    DiffieHellmanRatchet substitute that uses ML-KEM-1024 in place of X25519.

    Passed as the `diffie_hellman_ratchet_class` parameter to
    `DoubleRatchet.encrypt_initial_message` / `decrypt_initial_message`.
    The library calls our staticmethods directly; no instance methods are
    invoked by python-doubleratchet itself.
    """

    # Class-level handoff slot for the ciphertext produced during an
    # encapsulation step. The session layer reads and clears this via
    # pop_pending_ciphertext() immediately after each encrypt. See the
    # module docstring for the thread/concurrency caveat.
    _pending_ciphertext: Optional[bytes] = None

    # ── python-doubleratchet hooks ────────────────────────────────────────

    @staticmethod
    def _generate_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML-KEM-1024 keypair for one ratchet step.

        Returns
        -------
        (public_key, secret_key)
            public_key : 1568 bytes — transmitted in the message header.
            secret_key : 3168 bytes — retained locally until the next step.
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

        Branching on `own_priv` selects sender vs receiver semantics — see
        the module docstring for the overload of `other_pub`'s meaning.

        Parameters
        ----------
        own_priv  : None on the sender path; ML-KEM secret key bytes on the
                    receiver path.
        other_pub : Recipient's ML-KEM public key (sender path) OR ML-KEM
                    ciphertext from the incoming message header (receiver
                    path). Both happen to be 1568 bytes for ML-KEM-1024.

        Returns
        -------
        bytes : 32-byte shared secret, fed as `data` into RootChainKDF.

        Raises
        ------
        ValueError : if `other_pub` is not 1568 bytes for the active path.
        """
        if own_priv is None:
            # Sender — encapsulate to the recipient's ratchet public key.
            if len(other_pub) != KEM_PUBLIC_KEY_LEN:
                raise ValueError(
                    f"Sender path expects ML-KEM public key "
                    f"({KEM_PUBLIC_KEY_LEN} bytes), got {len(other_pub)}"
                )
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ciphertext, shared_secret = kem.encap_secret(other_pub)
            # Stash for the session layer to pick up via pop_pending_ciphertext.
            MLKEMRatchet._pending_ciphertext = ciphertext
            return shared_secret

        # Receiver — decapsulate using our retained secret key.
        if len(other_pub) != KEM_CIPHERTEXT_LEN:
            raise ValueError(
                f"Receiver path expects ML-KEM ciphertext "
                f"({KEM_CIPHERTEXT_LEN} bytes), got {len(other_pub)}"
            )
        with oqs.KeyEncapsulation(KEM_ALG, own_priv) as kem:
            shared_secret = kem.decap_secret(other_pub)
        return shared_secret

    # ── Session-layer hooks ───────────────────────────────────────────────

    @classmethod
    def pop_pending_ciphertext(cls) -> bytes:
        """
        Retrieve and clear the ciphertext produced by the most recent
        encapsulation.

        Called by the session layer immediately after every encrypt, so the
        ciphertext can be included in the outgoing message header.

        Raises
        ------
        RuntimeError : if no encapsulation has occurred since the last pop,
                       or if the receiver path was the last code run.
                       Treat this as a programmer error — a bare receive
                       step does not produce a ciphertext to send.
        """
        ct = cls._pending_ciphertext
        if ct is None:
            raise RuntimeError(
                "No pending ciphertext — pop_pending_ciphertext() was called "
                "without a preceding sender-path encapsulation."
            )
        cls._pending_ciphertext = None
        return ct
