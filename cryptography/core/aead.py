# core/aead.py
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib

def _derive_nonce(chain_index: int, message_index: int) -> bytes:
    """
    Derive a 12-byte nonce bound to both the ratchet chain step
    and the message position within that chain.
    Ensures (key, nonce) uniqueness even across concurrent chains.
    """
    material = chain_index.to_bytes(4, 'little') + \
               message_index.to_bytes(8, 'little')
    return material  # 12 bytes total, no two chains share a nonce

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes,
            chain_index: int, message_index: int) -> bytes:
    nonce = _derive_nonce(chain_index, message_index)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def decrypt(key: bytes, data: bytes, associated_data: bytes) -> bytes:
    nonce, ct = data[:12], data[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ct, associated_data)