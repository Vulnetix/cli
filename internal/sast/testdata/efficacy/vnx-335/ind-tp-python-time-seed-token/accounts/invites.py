import random
import string
import time

ALPHABET = string.ascii_letters + string.digits

~>random.seed(time.time())


def invite_token(length: int = 32) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))
