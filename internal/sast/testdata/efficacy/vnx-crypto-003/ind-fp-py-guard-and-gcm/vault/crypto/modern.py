import os

from Crypto.Cipher import AES


def make_cipher(key: bytes, mode=AES.MODE_GCM):
    if mode == AES.MODE_ECB:
        raise ValueError("ECB mode is not allowed")
    nonce = os.urandom(12)
    return AES.new(key, AES.MODE_GCM, nonce=nonce), nonce
