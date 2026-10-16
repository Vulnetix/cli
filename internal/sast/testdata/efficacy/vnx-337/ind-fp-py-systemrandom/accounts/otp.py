import random
import time

_sysrand = random.SystemRandom()


def generate_otp():
    started = time.time()
    code = "".join(str(_sysrand.randrange(10)) for _ in range(6))
    return code, started
