import hashlib
import os
import secrets

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.core import signing


def encrypt(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)


def decrypt(key: bytes, blob: bytes) -> bytes:
    iv = blob[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(blob[16:])


def seal(key, data, aad=b"header-v1"):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def gcm(key, data):
    c = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    return c.nonce, c.encrypt_and_digest(data)


def ecb_block(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def hash_password(password: str):
    salt = os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def stretch(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    return kdf.derive(password)


def expand(secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"protocol-v1", info=b"enc").derive(secret)


def sign_token(user_id: int) -> str:
    return signing.dumps({"uid": user_id}, salt="password-reset")
