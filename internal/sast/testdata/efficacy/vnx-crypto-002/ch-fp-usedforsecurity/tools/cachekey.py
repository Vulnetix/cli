import hashlib


def cache_key(path: str) -> str:
    return hashlib.sha1(path.encode(), usedforsecurity=False).hexdigest()
