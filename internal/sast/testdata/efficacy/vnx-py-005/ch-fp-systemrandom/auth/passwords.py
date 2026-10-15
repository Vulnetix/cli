import random
import secrets
import string

_sysrand = random.SystemRandom()


def generate_password(length=16):
    password = "".join(_sysrand.choice(string.ascii_letters) for _ in range(length))
    return password


def generate_token():
    token = "".join(random.SystemRandom().choice(string.hexdigits) for _ in range(32))
    return token


def api_key():
    return secrets.token_hex(32)
