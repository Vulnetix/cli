import hashlib


def create_hash(password: str) -> str:
    h = hashlib.new("md5")
~>    h.update(password.encode())
    return h.hexdigest()


def legacy_hash(secret_pw):
    hasher = hashlib.sha1()
    hasher.update(b"pepper")
~>    hasher.update(secret_pw.encode())
    return hasher.hexdigest()
