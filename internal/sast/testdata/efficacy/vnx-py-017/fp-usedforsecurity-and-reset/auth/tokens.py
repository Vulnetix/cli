import hashlib


def digest_auth(username, realm, password):
    a1 = f"{username}:{realm}:{password}"
    return hashlib.md5(a1.encode(), usedforsecurity=False).hexdigest()


def reset_link(user, password_reset_token):
    return hashlib.sha1(password_reset_token.encode()).hexdigest()
