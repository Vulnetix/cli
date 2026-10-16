import hashlib
import os
import secrets

import bcrypt


def hash_password(password):
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)


def hash_password2(password):
    salt = secrets.token_bytes(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def verify(password, stored):
    return bcrypt.hashpw(password.encode(), stored) == stored
