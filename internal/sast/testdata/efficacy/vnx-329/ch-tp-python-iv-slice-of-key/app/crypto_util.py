from Crypto.Cipher import AES


class Box:
    def __init__(self, secret_key: bytes):
        self._key = secret_key

    def encrypt(self, data: bytes) -> bytes:
~>        iv = self._key[:16]
        return AES.new(self._key, AES.MODE_CBC, iv).encrypt(data)

    def encrypt2(self, data: bytes) -> bytes:
~>        cipher = AES.new(self._key, AES.MODE_CBC, iv=self._key[:16])
        return cipher.encrypt(data)
