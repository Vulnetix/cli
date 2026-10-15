import random


def generate_otp():
~>    random.seed("static-otp-seed")
    otp = random.randint(100000, 999999)
    return str(otp)
