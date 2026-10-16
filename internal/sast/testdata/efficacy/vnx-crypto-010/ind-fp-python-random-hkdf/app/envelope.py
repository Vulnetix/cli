import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES


def subkey(master: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"envelope-v1", info=b"enc").derive(master)


def seal(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def open_blob(key: bytes, blob: bytes) -> bytes:
    iv = blob[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(blob[16:])


def from_settings(settings, data: bytes) -> bytes:
    return AES.new(settings.key, AES.MODE_CBC, settings.iv).encrypt(data)
