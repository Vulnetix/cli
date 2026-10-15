import hashlib


def authenticate(user, supplied):
    candidate = hashlib.sha256(supplied.encode()).hexdigest()
~>    if candidate == user.password_hash:
        return True
~>    return user.hashed_password == \
        hashlib.sha256(supplied.encode()).hexdigest()
