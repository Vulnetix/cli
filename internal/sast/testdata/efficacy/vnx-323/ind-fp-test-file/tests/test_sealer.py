import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = AESGCM.generate_key(bit_length=128)
NONCE = os.urandom(12)


def test_deterministic():
    assert AESGCM(KEY).encrypt(NONCE, b"x", None) == AESGCM(KEY).encrypt(NONCE, b"x", None)
