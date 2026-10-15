import hashlib

from Crypto.Cipher import AES


def seal(key: bytes, data: bytes) -> bytes:
~>    iv = hashlib.md5(key).digest()
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def seal2(master_key: bytes, data: bytes) -> bytes:
~>    iv = hashlib.sha256(master_key).digest()[:16]
    return AES.new(master_key, AES.MODE_CBC, iv).encrypt(data)
