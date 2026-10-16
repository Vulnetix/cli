from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def seal(data: bytes) -> bytes:
~>    cipher = AES.new(b"Kx9pLm2Qr7Tz4Vw8", AES.MODE_GCM, nonce=get_random_bytes(12))
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct
