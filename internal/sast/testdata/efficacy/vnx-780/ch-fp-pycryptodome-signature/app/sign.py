from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


def sign(key, data):
    return pkcs1_15.new(key).sign(SHA256.new(data))


def seal(key, data):
    return PKCS1_OAEP.new(key).encrypt(data)
