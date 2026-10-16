from hashlib import md5, sha256


def store_password(user, password):
    user.password_hash = md5(password.encode()).hexdigest()
    user.save()


def file_id(data):
    return sha256(data).hexdigest()
