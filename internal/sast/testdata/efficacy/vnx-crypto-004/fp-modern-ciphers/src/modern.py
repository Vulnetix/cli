import os

from Crypto.Cipher import AES, ChaCha20_Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def chacha(key, data):
    c = ChaCha20_Poly1305.new(key=key)
    return c.nonce + c.encrypt(data) + c.digest()


def gcm(key, data):
    return AES.new(key, AES.MODE_GCM).encrypt_and_digest(data)
