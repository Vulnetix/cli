import hashlib
from hashlib import md5


def cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def etag(body: bytes) -> str:
    return md5(body).hexdigest()


def file_sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def compare(password_hash, other):
    return password_hash == other
