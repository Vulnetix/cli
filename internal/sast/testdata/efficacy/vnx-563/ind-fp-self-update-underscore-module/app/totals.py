import os

TIMEOUT = int(os.environ.get("TIMEOUT", "30"))
TIMEOUT = max(TIMEOUT, 5)


class Defaults:
    retries = compute_retries = 3
    retries = 5


def running_total(values):
    total = values[0] * 1
    total = total + sum(values[1:])
    _ = os.getpid()
    _ = os.getppid()
    first, second = values[0], values[1]
    first, second = second, first
    return total, first, second


def debug_locals(x):
    y = x * 2
    y = x * 3
    return locals()
