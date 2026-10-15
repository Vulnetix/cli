import hashlib


def chunk_id(data: bytes) -> str:
    return hashlib.md5(
        data,
        usedforsecurity=False,
    ).hexdigest()
