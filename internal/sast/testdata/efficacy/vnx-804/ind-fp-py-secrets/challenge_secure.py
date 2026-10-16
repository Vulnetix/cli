import secrets
import random

_rng = random.SystemRandom()


def new_captcha():
    captcha_text = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(6))
    captcha_salt = _rng.randint(0, 99999)
    return captcha_text, captcha_salt


def pick_banner():
    return random.choice(["a", "b", "c"])
