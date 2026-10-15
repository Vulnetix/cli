import random

_sysrand = random.SystemRandom()


def token():
    token = "%032x" % _sysrand.getrandbits(128)
    return token


def jitter():
    random.seed()
    return random.random()
