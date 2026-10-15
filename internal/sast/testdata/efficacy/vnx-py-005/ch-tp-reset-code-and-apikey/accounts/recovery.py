import random
import string


def issue_reset(user):
~>    reset_code = "".join(random.choice(string.digits) for _ in range(6))
    user.reset_code = reset_code
    return reset_code


def new_key():
~>    api_key = "%032x" % random.getrandbits(128)
    return api_key
