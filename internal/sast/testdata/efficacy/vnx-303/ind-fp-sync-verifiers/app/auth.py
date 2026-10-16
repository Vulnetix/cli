import bcrypt
from werkzeug.security import check_password_hash


def login_bcrypt(user, password):
    if bcrypt.checkpw(password.encode(), user.password_hash):
        return user
    return None


def login_werkzeug(user, password):
    if check_password_hash(user.pw_hash, password):
        return user
    return None
