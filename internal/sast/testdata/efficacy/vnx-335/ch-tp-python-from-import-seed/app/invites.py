import string
import time
from random import choice, seed

ALPHABET = string.ascii_letters + string.digits


def make_invite():
~>    seed(int(time.time()))
    invite_token = "".join(choice(ALPHABET) for _ in range(24))
    return invite_token
