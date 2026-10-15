import hashlib
import os
import secrets

import bcrypt


def hash_password(password):
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def hash2(password):
    salt = secrets.token_bytes(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def hash3(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify(password, stored):
    salt = stored[:16]
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000) == stored[16:]


def check(password, hashed):
    return bcrypt.hashpw(password.encode(), hashed) == hashed
