import bcrypt

from .models import User


def login(username: str, password: str):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return None
~>    if bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()) == user.password_hash:
        return user
    return None
