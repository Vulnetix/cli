from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from django.conf import settings


class PartnerCipher:
    def __init__(self):
        self.key = settings.PARTNER_AES_KEY.encode()

    def encrypt(self, plain: str) -> bytes:
~>        iv = self.key[:16]
        return AES.new(self.key, AES.MODE_CBC, iv).encrypt(pad(plain.encode(), 16))
