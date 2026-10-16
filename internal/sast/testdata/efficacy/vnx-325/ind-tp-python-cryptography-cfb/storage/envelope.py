import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def seal(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
~>    encryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()
