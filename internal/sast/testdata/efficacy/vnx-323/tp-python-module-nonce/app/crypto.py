import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = AESGCM.generate_key(bit_length=256)
NONCE = os.urandom(12)


def seal(data: bytes) -> bytes:
~>    return AESGCM(KEY).encrypt(NONCE, data, None)


def seal_cbc(data):
~>    cipher = Cipher(algorithms.AES(KEY), modes.CBC(NONCE))
    return cipher.encryptor().update(data)
