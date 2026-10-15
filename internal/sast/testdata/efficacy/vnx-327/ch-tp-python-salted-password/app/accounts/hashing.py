import hashlib


def hash_password(password: str, salt: str) -> str:
~>    pw_hash = hashlib.md5((salt + password).encode("utf-8")).hexdigest()
    return pw_hash


def check(user, candidate):
~>    digest = hashlib.new(
        "sha1",
        candidate.encode(),
    ).hexdigest()
    return digest == user.password_hash
