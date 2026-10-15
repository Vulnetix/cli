import hashlib
import os


def salted(password):
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt.hex() + "$" + digest


def salted_update(password, user_salt):
    h = hashlib.sha256()
    h.update(user_salt)
    h.update(password.encode())
    return h.hexdigest()
