from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


def seal(pem, data):
    key = RSA.import_key(pem)
~>    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(data)
