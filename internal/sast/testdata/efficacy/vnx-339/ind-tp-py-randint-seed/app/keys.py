import random
import string


def generate_api_key(length=32):
~>    random.seed(random.randint(1, 5000))
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))
