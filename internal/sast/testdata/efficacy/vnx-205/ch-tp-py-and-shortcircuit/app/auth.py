import bcrypt

from .db import find_user


def authenticate(username, password):
    user = find_user(username)
~>    if user and bcrypt.checkpw(password.encode(), user.password_hash):
        return user
    return None
