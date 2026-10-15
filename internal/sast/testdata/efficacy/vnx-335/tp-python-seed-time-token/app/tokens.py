import random
import string
import time

~>random.seed(time.time())


def make_token():
    token = "".join(random.choice(string.ascii_letters) for _ in range(32))
    return token


def reseed():
~>    random.seed(int(time.time() * 1000))
