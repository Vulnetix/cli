import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def seal(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))


def unseal(key: bytes, blob: bytes) -> bytes:
    iv = blob[:16]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(blob[16:]), 16)
