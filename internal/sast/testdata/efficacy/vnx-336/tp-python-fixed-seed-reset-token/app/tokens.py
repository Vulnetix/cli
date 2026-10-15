import random
import string

~>random.seed(1337)
~>rng = random.Random(42)


def make_reset_token():
    return ''.join(random.choices(string.ascii_letters, k=32))


def new_api_key():
    api_key = rng.getrandbits(128)
    return f"{api_key:032x}"
