import bcrypt

from .db import find_user

DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())


def authenticate(username, password):
    user = find_user(username)
    if user is None:
        bcrypt.checkpw(password.encode(), DUMMY_HASH)
        return None
    if not bcrypt.checkpw(password.encode(), user.password_hash):
        return None
    return user
