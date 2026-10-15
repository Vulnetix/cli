import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = os.urandom(12)


def open_box(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)
