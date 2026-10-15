from hashlib import md5


def etag(body: bytes) -> str:
    return md5(body).hexdigest()


def remd5(text):
    return text.md5(text)
