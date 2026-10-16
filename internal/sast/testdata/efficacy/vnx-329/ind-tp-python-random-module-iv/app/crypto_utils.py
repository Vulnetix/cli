import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key: bytes, data: bytes) -> bytes:
~>    iv = random.randbytes(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(data) + enc.finalize()
