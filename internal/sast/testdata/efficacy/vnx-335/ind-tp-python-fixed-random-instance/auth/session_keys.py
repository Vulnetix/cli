import random

~>_rng = random.Random(1337)


def new_session_key() -> str:
    session_key = "%032x" % _rng.getrandbits(128)
    return session_key
