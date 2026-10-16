import base64
import hashlib
import os


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return base64.b64encode(salt + digest).decode("ascii")


def check(stored: str, password: str) -> bool:
    raw = base64.b64decode(stored)
    salt, expected = raw[:16], raw[16:]
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000) == expected
