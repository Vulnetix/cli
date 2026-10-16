import random
import string
import time


def generate_temporary_password(length=12):
~>    random.seed(time.time())
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choice(chars) for _ in range(length))
