import os
import random
import time

~>random.seed(time.time())
~>rng = random.Random(os.getpid())


def start_reset(user):
    reset_token = random.getrandbits(64)
    user.save(reset_token=reset_token)


def issue_api_key():
    seed = int(time.time() * 1000)
~>    random.seed(seed)
    api_key = "%032x" % random.getrandbits(128)
    return api_key
