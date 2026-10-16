import hashlib

~>SALT = b"s3cr3t-static-salt"


def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 200000)
