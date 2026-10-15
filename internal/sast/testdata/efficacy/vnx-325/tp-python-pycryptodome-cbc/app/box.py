from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(key, iv, data):
~>    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))


def decrypt(key, iv, blob):
    cipher = AES.new(
        key,
~>        AES.MODE_CBC,
        iv=iv,
    )
    return unpad(cipher.decrypt(blob), AES.block_size)


def stream(key, nonce):
~>    return AES.new(key, AES.MODE_CTR, nonce=nonce)
