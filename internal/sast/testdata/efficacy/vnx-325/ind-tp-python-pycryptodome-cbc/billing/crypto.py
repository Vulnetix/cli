from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt_card(key: bytes, pan: str) -> str:
    iv = get_random_bytes(16)
~>    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(pad(pan.encode(), AES.block_size))).decode()


def decrypt_card(key: bytes, blob: str) -> str:
    raw = b64decode(blob)
~>    cipher = AES.new(key, AES.MODE_CBC, raw[:16])
    return unpad(cipher.decrypt(raw[16:]), AES.block_size).decode()
