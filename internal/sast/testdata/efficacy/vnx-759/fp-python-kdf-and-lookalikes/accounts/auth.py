import hashlib
import os

import bcrypt


def register(user, password):
    salt = os.urandom(16)
    user.key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    user.hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user.scrypt = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def reset_link(user):
    # store a digest of the emailed token, never the token itself
    return hashlib.sha256(user.password_reset_token.encode()).hexdigest()


def file_digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def compare(candidate, user):
    if hashlib.md5(candidate).hexdigest() == user.etag:
        return True
    # hashlib.md5(password.encode()) was the old scheme
    print("hashlib.md5(password) is not used here")
    return False
