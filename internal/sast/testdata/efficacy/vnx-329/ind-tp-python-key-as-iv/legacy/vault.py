from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_record(key: bytes, data: bytes) -> bytes:
~>    cipher = AES.new(key, AES.MODE_CBC, key)
    return cipher.encrypt(pad(data, AES.block_size))
