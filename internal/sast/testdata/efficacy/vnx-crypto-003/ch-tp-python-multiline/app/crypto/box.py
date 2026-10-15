from Crypto.Cipher import DES3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def legacy(key, data):
~>    c = DES3.new(key, DES3.MODE_ECB)
    return c.encrypt(data)


def modern_wrong(key):
    return Cipher(
        algorithms.AES(key),
~>        modes.ECB(),
    ).encryptor()
