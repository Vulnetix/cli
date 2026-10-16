import random


def start_reset(user):
~>    reset_token = str(random.randint(100000, 999999))
    user.token = reset_token
    return reset_token
