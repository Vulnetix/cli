import random
import secrets
import string

_sys = random.SystemRandom()


def generate_session_token():
    return secrets.token_urlsafe(32)


def make_password():
    return ''.join(_sys.choice(string.ascii_letters) for _ in range(16))


def make_salt():
    return secrets.token_hex(16)


def otp():
    return str(secrets.randbelow(10**6)).zfill(6)
