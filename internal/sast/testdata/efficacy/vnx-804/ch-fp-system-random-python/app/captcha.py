import random
import secrets
import string

_rng = random.SystemRandom()
ALPHABET = string.ascii_uppercase + string.digits


def make_captcha_text(length=6):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def make_captcha_offset():
    return _rng.randint(0, 20)


def captcha_payload(text, image):
    # never return {"answer": text} here
    return {"image": image}
