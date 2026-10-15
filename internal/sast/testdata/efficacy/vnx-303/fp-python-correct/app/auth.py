import bcrypt
from werkzeug.security import check_password_hash, generate_password_hash


def login(user, password):
    if bcrypt.checkpw(password.encode(), user.password_hash):
        return True
    if bcrypt.hashpw(password.encode(), user.password_hash) == user.password_hash:
        return True
    return check_password_hash(user.password, password)


def register(username, password):
    user = User(username=username, password=generate_password_hash(password))
    user.salt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return user
