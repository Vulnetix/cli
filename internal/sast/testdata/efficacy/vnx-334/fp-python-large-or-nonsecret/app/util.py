import random
import secrets


def sample(items):
    idx = random.randint(0, len(items) - 1)
    return items[idx]


def jitter():
    delay = random.randint(1, 10)
    return delay


def token():
    return secrets.token_urlsafe(32)


def big_token():
    session_id = secrets.randbits(128)
    token = secrets.randbelow(2**128)
    return session_id, token
