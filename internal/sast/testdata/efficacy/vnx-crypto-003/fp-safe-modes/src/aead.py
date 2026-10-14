import os

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def seal(key, data):
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ct


def ctr(key, data):
    nonce = os.urandom(16)
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return nonce + enc.update(data) + enc.finalize()


def reject(mode):
    if mode == AES.MODE_ECB:
        raise ValueError("ECB is not allowed")
