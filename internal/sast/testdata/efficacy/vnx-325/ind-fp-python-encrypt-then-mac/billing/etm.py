import hashlib
import hmac
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def seal(enc_key: bytes, mac_key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return iv + ct + tag
