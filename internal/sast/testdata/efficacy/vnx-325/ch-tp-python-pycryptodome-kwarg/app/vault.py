from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def seal(key, data):
    iv = get_random_bytes(16)
~>    cipher = AES.new(key, mode=AES.MODE_OFB, iv=iv)
    return iv + cipher.encrypt(data)


def seal_stream(key, data):
~>    cipher = AES.new(key, AES.MODE_CFB, segment_size=128)
    return cipher.iv + cipher.encrypt(data)
