from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class LegacyCipher:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
~>        cipher = AES.new(self.key, AES.MODE_CBC, b'fedcba9876543210')
        return cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, blob: bytes) -> bytes:
        cipher = AES.new(
            self.key,
            AES.MODE_CBC,
~>            iv=b'fedcba9876543210',
        )
        return unpad(cipher.decrypt(blob), AES.block_size)
