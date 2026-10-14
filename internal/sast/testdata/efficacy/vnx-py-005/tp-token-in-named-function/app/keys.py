import random
import string


def generate_api_key():
    chars = string.ascii_lowercase + string.digits
~>    return "".join(random.choices(chars, k=16))


def make_reset_token(length=32):
~>    return "".join(random.choice(string.ascii_letters) for _ in range(length))
