from werkzeug.security import check_password_hash


def login(user, form):
    if check_password_hash(user.password_hash, form["password"]):
        return True
    if user.password_hash == hash_password(form["password"]):
        return True
    return False
