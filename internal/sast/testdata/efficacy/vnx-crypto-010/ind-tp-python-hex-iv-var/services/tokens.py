import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

~>NONCE = bytes.fromhex("000102030405060708090a0b")


def seal(key: bytes, payload: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.GCM(NONCE)).encryptor()
    return enc.update(payload) + enc.finalize() + enc.tag


def hash_pin(pin: str) -> bytes:
~>    return hashlib.pbkdf2_hmac("sha256", pin.encode(), b"pin-salt", 200_000)
