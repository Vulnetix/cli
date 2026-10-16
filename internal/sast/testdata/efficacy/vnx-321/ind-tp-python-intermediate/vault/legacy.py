from Crypto.Cipher import AES


def legacy_encrypt(data: bytes, iv: bytes) -> bytes:
~>    key = b"Rq7Lx2Mz9Pk4Wn8TbV5cX1aS"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)
