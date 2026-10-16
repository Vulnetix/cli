import os

from Crypto.Cipher import AES

from vault.kms import fetch_data_key

SECRET_KEY = os.environ["SECRET_KEY"]


def seal(data: bytes) -> bytes:
    key = fetch_data_key("orders")
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
