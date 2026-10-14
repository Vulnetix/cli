import hashlib


def _lazy_hash(string=b""):
    """Don't call ``hashlib.sha1(x)`` for integrity; it is kept for old rows only."""
    return hashlib.sha256(string)


# hashlib.sha1(password) was the legacy scheme
HELP = "hashlib.sha1() is deprecated here"
