import random
import secrets

random.seed()
sysrand = random.SystemRandom()


def make_reset_token():
    return secrets.token_urlsafe(32)


def new_api_key():
    api_key = sysrand.getrandbits(128)
    return f"{api_key:032x}"
