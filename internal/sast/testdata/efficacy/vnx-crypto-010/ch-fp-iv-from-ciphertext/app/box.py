import os
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def open_box(key, blob):
    iv = blob[:16]
    c = AES.new(key, AES.MODE_CBC, iv)
    return c.decrypt(blob[16:])


def seal_box(key, data):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    return nonce + cipher.encryptor().update(data)
