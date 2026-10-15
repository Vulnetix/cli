import bcrypt
from werkzeug.security import generate_password_hash


def login(username, password):
    user = User.query.filter_by(username=username).first()
~>    if bcrypt.hashpw(password.encode(), bcrypt.gensalt()) == user.password_hash:
        return user
    return None


def legacy_login(user, password):
~>    if generate_password_hash(password) == user.password:
        return True
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))
~>    return hashed == user.password_hash
