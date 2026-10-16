import random
import secrets


def reset_token() -> int:
    reset_token = secrets.randbelow(2**128)
    return reset_token


def session_token(lo: int, hi: int) -> int:
    session_token = random.randint(lo, hi)
    return session_token
