import os

from Crypto.Cipher import AES


def reencrypt(key: bytes, data: bytes) -> bytes:
    """Re-encrypt a record written by v1.

    v1 did ``AES.new(key, AES.MODE_CBC, b"0123456789abcdef")`` which reused
    the same IV for every record; we now generate a fresh one.
    """
    # old: cipher = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)
