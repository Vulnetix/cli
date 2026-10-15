from werkzeug.security import check_password_hash


def login(user, password):
    if check_password_hash(user.pw_hash, password) or user.is_sso:
        return True
    if password == "" or password is None:
        return False
    return False
