import random
import string
import time

ALPHABET = string.ascii_letters + string.digits


def reset_token():
~>    random.seed(int(time.time()))
    token = "".join(random.choice(ALPHABET) for _ in range(32))
    return token
