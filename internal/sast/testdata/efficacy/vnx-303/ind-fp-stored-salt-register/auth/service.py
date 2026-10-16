import bcrypt

from .models import User, db


def verify(user, password):
    stored = user.password_hash
    if bcrypt.hashpw(password.encode(), stored) == stored:
        return True
    return False


def register(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    user = User(username=username, password_hash=hashed)
    db.session.add(user)
    db.session.commit()
    return user
