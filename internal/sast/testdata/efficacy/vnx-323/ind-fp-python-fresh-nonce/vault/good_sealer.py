import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = AESGCM.generate_key(bit_length=256)


def seal(data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)
