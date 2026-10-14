import hashlib
import os

import bcrypt


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + ":" + dk.hex()


def hash_password_bcrypt(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def fingerprint(password: str) -> str:
    return hashlib.sha256(hashlib.scrypt(password.encode(), salt=b"x", n=2**14, r=8, p=1)).hexdigest()
