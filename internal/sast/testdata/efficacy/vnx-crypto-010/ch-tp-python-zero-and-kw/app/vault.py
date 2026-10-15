from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES


def seal(key, data):
~>    cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def seal_legacy(key, data):
~>    c = AES.new(key, AES.MODE_CBC, iv=b'abcdefghijklmnop')
    return c.encrypt(data)


def seal_gcm(key, data):
~>    c = AES.new(key, AES.MODE_GCM, nonce=bytes(12))
    return c.encrypt_and_digest(data)
