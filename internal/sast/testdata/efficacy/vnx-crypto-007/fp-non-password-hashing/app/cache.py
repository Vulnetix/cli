import hashlib


def cache_key(url):
    return hashlib.sha256(url.encode()).hexdigest()


def reset_token_digest(password_reset_token):
    return hashlib.sha256(password_reset_token.encode()).hexdigest()


def passport_id(passport_number):
    return hashlib.sha1(passport_number.encode()).hexdigest()
