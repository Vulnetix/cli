import random


def make_reset_token(username):
~>    random.seed(random.randint(0, 999))
    return "%016x" % random.getrandbits(64)


def make_invite_code(username):
~>    random.seed(len(username))
    invite_code = random.randint(100000, 999999)
    return invite_code
