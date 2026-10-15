import hashlib


def cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()


def etag(body):
    return '"%s"' % hashlib.sha1(body).hexdigest()


def checksum(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()
