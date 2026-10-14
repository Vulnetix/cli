import pyaes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_token(key, token):
~>    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(token, 16))


def encrypt_wrapped(key, data):
    cipher = AES.new(
        key,
~>        AES.MODE_ECB,
    )
    return cipher.encrypt(pad(data, 16))


def keyword_mode(key, data):
~>    return AES.new(key=key, mode=AES.MODE_ECB).encrypt(pad(data, 16))


def with_cryptography(key, block):
~>    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def with_pyaes(key, block):
~>    aes = pyaes.AESModeOfOperationECB(key)
    return aes.encrypt(block)


def legacy_pycrypto_default(key, block):
~>    return AES.new(key).encrypt(block)
