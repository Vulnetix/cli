import random as rnd
from random import randrange


def make_salt():
~>    salt = rnd.randint(0, 2**32)
    return str(salt)


def send_otp(phone):
~>    otp = randrange(100000, 999999)
    sms(phone, otp)


def nonce():
~>    request_nonce = rnd.getrandbits(64)
    return request_nonce
