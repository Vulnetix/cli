from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Vault:
    def __init__(self, key):
        self.key = key
        self.nonce = get_random_bytes(12)

    def encrypt(self, data):
~>        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        return cipher.encrypt_and_digest(data)
