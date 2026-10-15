import hashlib
import time


def make_reset(user):
~>    reset_token = hashlib.md5(user.email.encode()).hexdigest()
~>    user.reset_key = str(time.time())
    return reset_token
