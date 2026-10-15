import random
import secrets
import time

random.seed(time.time())


def roll():
    return random.randint(1, 6)


def token():
    token = secrets.token_urlsafe(32)
    return token
