import random

~>rng = random.Random(1337)


def api_key():
    api_key = "%032x" % rng.getrandbits(128)
    return api_key
