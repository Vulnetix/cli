import os
import random
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt(key, data):
    iv = get_random_bytes(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def encrypt2(key, data):
    iv = os.urandom(16)
    return iv + AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)


def encrypt3(key, data):
    iv = secrets.token_bytes(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def decrypt(key, blob):
    iv = blob[:16]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(blob[16:])


def shuffle(items):
    random.shuffle(items)
    keys = list(items)
    first = keys[:16]
    return first
