import secrets
import string


def generate_captcha():
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(6))


def generate_captcha_sys():
    rng = random.SystemRandom()
    return rng.randint(1000, 9999)
