import hashlib
import os

import bcrypt


def derive(password: str) -> bytes:
    salt = os.urandom(16)
~>    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 5000)


def quick_hash(password: str) -> bytes:
~>    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=6))
