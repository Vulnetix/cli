from Crypto.Cipher import ARC4, Blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def rc4(key, data):
~>    return ARC4.new(key).encrypt(data)


def bf(key, iv):
~>    return Blowfish.new(key, Blowfish.MODE_CBC, iv)


def tdes(key, iv):
    return Cipher(
~>        algorithms.TripleDES(key),
        modes.CBC(iv),
    ).encryptor()
