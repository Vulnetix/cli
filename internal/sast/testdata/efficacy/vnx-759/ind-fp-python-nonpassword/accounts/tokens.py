import hashlib


def etag(body):
    return hashlib.sha256(body).hexdigest()


def reset_token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def file_digest(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


# do not do hashlib.sha256(password) here
