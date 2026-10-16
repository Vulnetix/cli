import hashlib


def bucket_for(token: str, buckets: int) -> int:
    digest = hashlib.md5(token.encode(), usedforsecurity=False).digest()
    return int.from_bytes(digest[:4], "big") % buckets
