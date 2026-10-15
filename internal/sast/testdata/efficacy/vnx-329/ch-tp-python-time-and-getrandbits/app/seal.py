import random
import time

from Crypto.Cipher import AES


def seal(key, data):
~>    iv = bytes(random.getrandbits(8) for _ in range(16))
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def seal_ts(key, data):
~>    iv = str(int(time.time())).zfill(16).encode()
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)
