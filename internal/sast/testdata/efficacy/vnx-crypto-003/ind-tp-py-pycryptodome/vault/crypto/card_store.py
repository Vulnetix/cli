from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class CardStore:
    def __init__(self, key: bytes):
        self._key = key

    def seal(self, pan: str) -> bytes:
~>        cipher = AES.new(self._key, AES.MODE_ECB)
        return cipher.encrypt(pad(pan.encode(), AES.block_size))
