import hashlib


def _h(x):
    """HTTP Digest (RFC 2617) mandates MD5; never call hashlib.md5(x) for passwords."""
    return hashlib.md5(x, usedforsecurity=False).hexdigest()


def _etag(body):
    return hashlib.md5(
        body,
        usedforsecurity=False,
    ).hexdigest()
