import hashlib


def store_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def named(data):
    return hashlib.new("sha3_256", data).hexdigest()


def blake(data):
    return hashlib.blake2b(data).hexdigest()
