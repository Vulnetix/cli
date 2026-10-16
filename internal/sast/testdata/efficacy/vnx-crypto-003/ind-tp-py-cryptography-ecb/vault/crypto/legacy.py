from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def encrypt_record(key: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
~>    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()
