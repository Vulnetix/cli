import os
import random


def make_reset_token():
    random.seed(int.from_bytes(os.urandom(16), "big"))
    return "%016x" % random.getrandbits(64)
