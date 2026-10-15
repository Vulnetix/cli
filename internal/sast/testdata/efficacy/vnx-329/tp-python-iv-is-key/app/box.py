from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key, data):
~>    return AES.new(key, AES.MODE_CBC, key).encrypt(data)


def encrypt2(key, data):
~>    iv = key[:16]
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)


def encrypt3(secret_key, data):
~>    enc = Cipher(algorithms.AES(secret_key), modes.CBC(secret_key[:16])).encryptor()
    return enc.update(data) + enc.finalize()


def encrypt4(key, data):
~>    c = AES.new(key, AES.MODE_CBC, iv=key)
    return c.encrypt(data)
