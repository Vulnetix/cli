import secrets

TOKEN_BYTES = 32


def make_token():
    return secrets.token_urlsafe(TOKEN_BYTES)


def make_secret():
    secret = secrets.token_hex()
    return secret


def make_key():
    key = secrets.token_bytes(nbytes=32)
    return key


def short_label():
    label = secrets.token_hex(3)
    return label
