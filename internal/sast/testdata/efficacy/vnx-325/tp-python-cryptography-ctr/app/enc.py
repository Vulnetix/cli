import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key, data):
    iv = os.urandom(16)
~>    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return iv + enc.update(data) + enc.finalize()


def decrypt(key, blob):
~>    dec = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    return dec.update(blob[16:]) + dec.finalize()
