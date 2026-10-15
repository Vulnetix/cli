import hashlib
import os


def derive(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 600_000)
