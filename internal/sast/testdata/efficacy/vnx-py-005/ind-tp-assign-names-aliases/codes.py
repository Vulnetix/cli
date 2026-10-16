import random as r
from random import randint


def send_codes(user):
~>    otp = str(r.randint(0, 999999)).zfill(6)
~>    reset_code = randint(100000, 999999)
~>    user.api_key = r.getrandbits(128)
    return otp, reset_code
