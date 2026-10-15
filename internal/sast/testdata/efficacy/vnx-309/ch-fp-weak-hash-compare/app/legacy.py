import hashlib


def verify(user, password):
    digest = hashlib.sha256(password.encode()).hexdigest()
    return user.password_hash == digest
