import os
import time

MAX_AGE = 7 * 24 * 3600


def prune(path):
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if time.time() - os.path.getmtime(full) > MAX_AGE:
            os.remove(full)
    old = os.path.join(path, "2024-01-01.log")
    if os.path.exists(old):
        os.unlink(old)
