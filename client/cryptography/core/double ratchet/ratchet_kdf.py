"""
core/ratchet_kdf.py

KDF implementations required by python-doubleratchet.

python-doubleratchet requires two KDF types:
  - Root chain KDF  (KDF_RK): takes DH output + current root key → new root key + chain key
  - Message chain KDF (KDF_CK): takes chain key → message key + next chain key

Both must be capable of deriving 64 bytes total (two 32-byte keys).

We implement both using HKDF-SHA256 with domain-separated info strings from
kdf.py, wiring our existing infrastructure into the python-doubleratchet API.

References:
  Signal DR spec §3.1 KDF_RK: https://signal.org/docs/specifications/doubleratchet/
  Signal DR spec §3.1 KDF_CK: https://signal.org/docs/specifications/doubleratchet/
  RFC 5869 HKDF:               https://www.rfc-editor.org/rfc/rfc5869
"""

from __future__ import annotations

from doubleratchet.kdf import KDF

from core.kdf import hkdf_derive, INFO_ROOT_KDF, INFO_CHAIN_KDF


class RootChainKDF(KDF):
    """
    Root chain KDF (KDF_RK in the Signal spec).

    Called on every DH ratchet step to derive:
      - A new root key (first 32 bytes)
      - A new chain key (next 32 bytes)

    Input:
      key  = current root key (32 bytes, used as HKDF salt)
      data = DH/KEM shared secret (32 bytes, used as HKDF IKM)

    Output: 64 bytes (new_root_key || new_chain_key)

    The root key acts as the salt rather than IKM — this matches the Signal
    spec's KDF_RK(rk, dh_out) formulation where rk is the chaining variable.
    """

    @staticmethod
    def calculate(length: int, key: bytes, data: bytes) -> bytes:
        """
        Derive `length` bytes from key (root key) and data (DH output).

        Parameters
        ----------
        length : number of bytes to derive (python-doubleratchet passes 64)
        key    : current root key — used as HKDF salt
        data   : DH/KEM shared secret — used as HKDF IKM

        Returns
        -------
        bytes : `length` bytes of derived key material
        """
        return hkdf_derive(
            ikm    = data,   # DH/KEM output is the input key material
            salt   = key,    # current root key is the salt (Signal spec §3.1)
            info   = INFO_ROOT_KDF,
            length = length,
        )


class MessageChainKDF(KDF):
    """
    Message chain KDF (KDF_CK in the Signal spec).

    Called on every message to derive:
      - A message key (first 32 bytes) — used to encrypt/decrypt this message
      - The next chain key (next 32 bytes) — fed back into the chain

    Input:
      key  = current chain key (32 bytes, used as HKDF IKM)
      data = message chain constant (a fixed byte string, used as HKDF salt)

    Output: 64 bytes (message_key || next_chain_key)

    The chain constant is passed by python-doubleratchet as the `data`
    parameter. We use it as the HKDF salt to provide domain separation
    between successive chain steps.
    """

    @staticmethod
    def calculate(length: int, key: bytes, data: bytes) -> bytes:
        """
        Derive `length` bytes from key (chain key) and data (chain constant).

        Parameters
        ----------
        length : number of bytes to derive (python-doubleratchet passes 64)
        key    : current chain key — used as HKDF IKM
        data   : message chain constant — used as HKDF salt

        Returns
        -------
        bytes : `length` bytes of derived key material
        """
        return hkdf_derive(
            ikm    = key,    # chain key is the input key material
            salt   = data,   # chain constant is the salt
            info   = INFO_CHAIN_KDF,
            length = length,
        )
