import base64
import hashlib
import os


def store(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return base64.b64encode(salt + dk).decode()


def fingerprint(password):
    return base64.b64encode(hashlib.sha256(password.encode()).digest())
