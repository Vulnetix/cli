import random
import secrets
import string


def generate_api_key():
    return secrets.token_urlsafe(32)


def make_reset_token(length=32):
    sysrand = random.SystemRandom()
    return "".join(sysrand.choice(string.ascii_letters) for _ in range(length))


def make_password():
    return "".join(secrets.choice(string.ascii_letters) for _ in range(20))
