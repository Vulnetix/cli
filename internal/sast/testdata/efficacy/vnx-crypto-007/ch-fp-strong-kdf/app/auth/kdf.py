import hashlib

import bcrypt

ITERATIONS = 600_000


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


def bc(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
