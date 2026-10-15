import random


def generate_captcha_code():
~>    code = random.randint(1000, 9999)
    return str(code)
