import hashlib

import bcrypt

~>SALT = b"s3cr3t-static-salt"


def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 600_000)


def legacy(password):
~>    return hashlib.pbkdf2_hmac('sha256', password.encode(), b'NaCl', 100000)


def legacy_concat(password):
~>    salt = "fixed"
    return hashlib.sha256((salt + password).encode()).hexdigest()


def fixed_bcrypt(password):
~>    return bcrypt.hashpw(password.encode(), b"$2b$12$abcdefghijklmnopqrstuu")
