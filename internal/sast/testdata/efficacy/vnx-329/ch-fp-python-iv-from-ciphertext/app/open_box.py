import os

from Crypto.Cipher import AES


def decrypt(key, blob):
    iv, body = blob[:16], blob[16:]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(body)


def encrypt(key, data):
    iv = os.urandom(16)
    return iv + AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)


def wrap(key_id, data):
    iv = os.urandom(16)
    return {"key_id": key_id, "iv": iv.hex(), "data": data}
