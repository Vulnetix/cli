import hashlib


def etag(body: bytes) -> str:
    # MD5 is fine here: this is a cache validator, not a password hash
    return hashlib.md5(body).hexdigest()


HELP = "never call hashlib.md5(password) for credentials"
