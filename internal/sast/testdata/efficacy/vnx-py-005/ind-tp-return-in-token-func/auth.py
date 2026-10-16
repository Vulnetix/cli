import random
import string


def generate_session_token():
~>    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


def make_salt():
~>    return str(random.randint(100000, 999999))
