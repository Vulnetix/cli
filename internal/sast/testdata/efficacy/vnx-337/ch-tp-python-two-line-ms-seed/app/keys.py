import random
import time


def make_api_key():
    seed = int(time.time() * 1000)
~>    random.seed(seed)
    api_key = "%032x" % random.getrandbits(128)
    return api_key
