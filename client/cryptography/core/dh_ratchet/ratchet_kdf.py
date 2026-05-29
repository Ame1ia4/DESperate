"""
core/dh_ratchet/ratchet_kdf.py

KDF implementations required by python-doubleratchet.

The Syndace library defines an abstract `doubleratchet.kdf.KDF` base with a
single staticmethod `calculate(length, key, data) -> bytes`. The library
invokes it twice per message exchange:

  RootChainKDF — invoked once per DH (here ML-KEM) ratchet step.
      key  = current root key  (used as HKDF salt)
      data = DH/KEM shared secret  (used as HKDF IKM)
      → 64 bytes = new_root_key (32) || new_chain_key (32)

  MessageChainKDF — invoked once per message in a sending/receiving chain.
      key  = current chain key  (used as HKDF IKM)
      data = message chain constant  (used as HKDF salt — domain separator)
      → 64 bytes = message_key (32) || next_chain_key (32)

The IKM/salt assignment is asymmetric between the two KDFs because the
Signal spec models KDF_RK as "advance a chaining root with new randomness"
(root is the chaining variable, DH output is fresh material) while KDF_CK
is "advance a chain with a fixed constant" (the chain key is the only
secret, the constant just gives HKDF a non-empty salt for domain separation).

Domain separation is enforced via INFO_ROOT_KDF and INFO_CHAIN_KDF from
core/kdf.py. With different info strings, even if an attacker contrived
identical (key, data) inputs to both KDFs, the outputs would still differ.

References
----------
Signal DR spec §3.1 KDF_RK / KDF_CK:
    https://signal.org/docs/specifications/doubleratchet/
RFC 5869 HKDF:
    https://www.rfc-editor.org/rfc/rfc5869
"""

from __future__ import annotations

from doubleratchet.kdf import KDF

from core.kdf import hkdf_derive, INFO_ROOT_KDF, INFO_CHAIN_KDF


class RootChainKDF(KDF):
    """
    Root chain KDF (Signal DR spec KDF_RK).

    Called once per DH/KEM ratchet step. Combines the current root key with
    a freshly-derived KEM shared secret to produce the next root key and a
    new chain key.
    """

    @staticmethod
    def calculate(length: int, key: bytes, data: bytes) -> bytes:
        """
        Derive `length` bytes from (key, data).

        Parameters
        ----------
        length : output length in bytes. python-doubleratchet always passes 64.
        key    : current root key — used as HKDF salt.
        data   : KEM-derived shared secret — used as HKDF IKM.

        Returns
        -------
        bytes : `length` bytes of derived key material.
                By convention the caller treats bytes[:32] as the new root
                key and bytes[32:64] as the new chain key.
        """
        return hkdf_derive(
            ikm    = data,
            salt   = key,
            info   = INFO_ROOT_KDF,
            length = length,
        )


class MessageChainKDF(KDF):
    """
    Message chain KDF (Signal DR spec KDF_CK).

    Called once per message. Splits the chain key into a per-message key
    and the next chain key. The chain constant is a fixed byte string used
    only to give HKDF a non-empty salt; it is not secret.
    """

    @staticmethod
    def calculate(length: int, key: bytes, data: bytes) -> bytes:
        """
        Derive `length` bytes from (key, data).

        Parameters
        ----------
        length : output length in bytes. python-doubleratchet always passes 64.
        key    : current chain key — used as HKDF IKM.
        data   : message chain constant — used as HKDF salt.

        Returns
        -------
        bytes : `length` bytes of derived key material.
                By convention the caller treats bytes[:32] as the message
                key for this message and bytes[32:64] as the next chain key.
        """
        return hkdf_derive(
            ikm    = key,
            salt   = data,
            info   = INFO_CHAIN_KDF,
            length = length,
        )
