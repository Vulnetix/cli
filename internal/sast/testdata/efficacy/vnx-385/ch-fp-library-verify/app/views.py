import hmac

import bcrypt
from werkzeug.security import check_password_hash


def login(user, password):
    if not password:
        return False
    if user.password is None:
        return False
    if check_password_hash(user.password_hash, password):
        return True
    if bcrypt.checkpw(password.encode(), user.password_hash):
        return True
    return hmac.compare_digest(user.password_hash, hash_it(password))


def changed(user, other_time):
    return user.password_changed_at == other_time
