import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
