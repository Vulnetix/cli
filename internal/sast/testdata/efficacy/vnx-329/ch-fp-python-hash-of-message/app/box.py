import hashlib
import os

from Crypto.Cipher import AES


def seal(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
    digest = hashlib.sha256(key + data).digest()
    key_id = hashlib.sha256(key).hexdigest()[:8]
    return key_id.encode() + iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data) + digest
