import bcrypt


def login(user, submitted):
    candidate = bcrypt.hashpw(submitted.encode(), bcrypt.gensalt(rounds=12))
~>    if candidate == user.password_hash:
        return True
    return False
