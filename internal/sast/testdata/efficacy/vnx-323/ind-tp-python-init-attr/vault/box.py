import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Box:
    def __init__(self, key: bytes):
        self.key = key
        self.iv = os.urandom(16)

    def encrypt(self, padded: bytes) -> bytes:
~>        encryptor = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).encryptor()
        return encryptor.update(padded) + encryptor.finalize()
