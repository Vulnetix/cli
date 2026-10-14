import random as rnd
from random import randint, choice as pick


def send_login_code(user):
~>    otpN = randint(100, 999)
~>    verification_code = "".join(pick("0123456789") for _ in range(6))
~>    user.nonce = rnd.randrange(1 << 30)
    return otpN, verification_code
