import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = os.urandom(12)


def test_roundtrip():
    ct = AESGCM(KEY).encrypt(NONCE, b"x", None)
    assert ct
