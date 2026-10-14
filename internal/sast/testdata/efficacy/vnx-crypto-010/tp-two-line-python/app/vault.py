import hashlib

from Crypto.Cipher import AES, ChaCha20
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

~>IV = b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x00"


class Vault:
~>    SALT = "vault-salt".encode("utf-8")

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, IV)
        return cipher.encrypt(data)

    def derive(self, password: str) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), self.SALT, 600_000)


def derive_key(password: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
~>        salt=b"application-salt",
        iterations=480_000,
    )
    return kdf.derive(password)


def stream(key, data):
~>    nonce = bytes(12)
    return ChaCha20.new(key=key, nonce=nonce).encrypt(data)


def hash_pin(pin: str) -> bytes:
~>    return hashlib.pbkdf2_hmac('sha1', pin.encode(), b'pinsalt', 1000)


def gcm(key, data):
~>    c = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex("000102030405060708090a0b"))
    return c.encrypt_and_digest(data)


def seal(key, data):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
~>    nonce = b"\x00" * 12
    return aesgcm.encrypt(nonce, data, None)
