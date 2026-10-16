import hashlib
import os

import bcrypt


def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return salt + dk


def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
