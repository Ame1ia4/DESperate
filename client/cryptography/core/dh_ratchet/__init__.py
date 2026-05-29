"""
core/dh_ratchet/

ML-KEM-1024 Double Ratchet for the DES-perate secure messaging client.

This package implements the symmetric and asymmetric ratchet steps of the
Signal Double Ratchet, substituting the X25519 DH step for an ML-KEM-1024
encapsulation/decapsulation step. It is layered on top of the Syndace
python-doubleratchet library, which handles the message-chain bookkeeping,
out-of-order message buffering, and JSON serialisation.

Layout
------
    dh_ratchet.py    — MLKEMRatchet
                       DiffieHellmanRatchet subclass that swaps X25519 DH
                       for ML-KEM-1024 encapsulation.

    ratchet_kdf.py   — RootChainKDF, MessageChainKDF
                       HKDF-SHA256 wrappers with domain-separated info
                       strings from core/kdf.py.

    session.py       — RatchetSession
                       Lifecycle, wire format, and state persistence.

References
----------
Signal Double Ratchet spec:
    https://signal.org/docs/specifications/doubleratchet/
Signal PQXDH spec (post-quantum braid):
    https://signal.org/docs/specifications/pqxdh/
FIPS 203 (ML-KEM-1024):
    https://doi.org/10.6028/NIST.FIPS.203
python-doubleratchet (Syndace):
    https://github.com/Syndace/python-doubleratchet
"""

from core.dh_ratchet.dh_ratchet  import MLKEMRatchet
from core.dh_ratchet.ratchet_kdf import RootChainKDF, MessageChainKDF
from core.dh_ratchet.session     import RatchetSession

__all__ = [
    "MLKEMRatchet",
    "RootChainKDF",
    "MessageChainKDF",
    "RatchetSession",
]
