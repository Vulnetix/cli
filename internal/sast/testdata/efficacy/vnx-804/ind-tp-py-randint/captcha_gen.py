import random


def make_captcha():
~>    code = random.randint(1000, 9999)
    return str(code)
