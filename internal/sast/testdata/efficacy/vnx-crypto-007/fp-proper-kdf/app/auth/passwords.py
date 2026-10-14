import hashlib

import bcrypt
from argon2 import PasswordHasher

ph = PasswordHasher()


def store(password):
    return ph.hash(password)


def store_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
