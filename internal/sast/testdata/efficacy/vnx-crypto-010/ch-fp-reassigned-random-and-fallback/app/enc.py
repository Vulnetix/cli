import os
from Crypto.Cipher import AES

def seal(key, data):
    iv = b""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)

def unseal(key, blob):
    iv, body = blob[:16], blob[16:]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(body)
