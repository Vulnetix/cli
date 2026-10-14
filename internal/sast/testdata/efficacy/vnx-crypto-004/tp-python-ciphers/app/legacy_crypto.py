import pyDes
from Crypto.Cipher import ARC4, DES, Blowfish
from Crypto.Cipher import DES3 as TDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_card(key, iv, data):
~>    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(data)


def encrypt_3des(key, iv, data):
~>    return TDES.new(key, TDES.MODE_CBC, iv).encrypt(data)


def stream(key, data):
~>    return ARC4.new(key).encrypt(data)


def blowfish(key, iv, data):
~>    return Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(data)


def via_cryptography(key, iv, data):
~>    enc = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def rc4_cryptography(key, data):
~>    return Cipher(algorithms.ARC4(key), mode=None).encryptor().update(data)


def pure_python(key, data):
~>    k = pyDes.triple_des(key, pyDes.CBC, b"\0" * 8, pad=None, padmode=pyDes.PAD_PKCS5)
    return k.encrypt(data)
