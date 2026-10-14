import hashlib

import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 1000


def derive(password, salt):
~>    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)


def derive_const(password, salt):
~>    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


def derive_kdf(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
~>        iterations=5000,
    )
    return kdf.derive(password)


def cheap_bcrypt(password):
~>    return bcrypt.hashpw(password, bcrypt.gensalt(rounds=4))
