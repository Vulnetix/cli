import random
import time
from Crypto.Cipher import AES


def encrypt(key, data):
~>    iv = random.randbytes(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def encrypt2(key, data):
~>    iv = bytes([random.randint(0, 255) for _ in range(16)])
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def encrypt3(key, data):
~>    iv = str(int(time.time())).zfill(16).encode()
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)
