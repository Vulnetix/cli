from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def encrypt_blob(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(
        algorithms.AES(key),
~>        modes.CBC(iv),
    )
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def stream(key, nonce, data):
~>    enc = Cipher(algorithms.AES256(key), modes.OFB(nonce)).encryptor()
    return enc.update(data) + enc.finalize()
