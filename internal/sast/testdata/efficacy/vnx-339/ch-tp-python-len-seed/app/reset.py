import random
import string


def password_reset_token(username):
~>    random.seed(len(username))
    reset_token = "".join(random.choice(string.hexdigits) for _ in range(32))
    return reset_token
