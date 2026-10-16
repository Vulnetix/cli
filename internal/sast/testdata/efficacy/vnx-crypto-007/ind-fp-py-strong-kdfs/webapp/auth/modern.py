import hashlib
import os

import bcrypt
from argon2 import PasswordHasher

_ph = PasswordHasher()


def argon(password: str) -> str:
    return _ph.hash(password)


def bc(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def pbkdf2(password: str) -> bytes:
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
