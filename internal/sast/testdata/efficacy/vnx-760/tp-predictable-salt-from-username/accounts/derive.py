import hashlib


def derive(user, password):
~>    return hashlib.pbkdf2_hmac("sha256", password.encode(), user.username.encode(), 200_000)
