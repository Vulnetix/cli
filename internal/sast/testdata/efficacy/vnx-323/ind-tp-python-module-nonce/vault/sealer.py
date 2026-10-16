import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = AESGCM.generate_key(bit_length=256)
NONCE = os.urandom(12)


def seal(data: bytes, aad: bytes = None) -> bytes:
~>    return AESGCM(KEY).encrypt(NONCE, data, aad)
