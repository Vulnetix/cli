import random
import time

from flask import request


def backoff(attempt):
    delay = min(60, 2 ** attempt) + random.uniform(0, 1)
    time.sleep(delay)


def sample_rows(rows):
    return random.sample(rows, k=min(10, len(rows)))


def audit():
    # reset_token = str(random.randint(100000, 999999)) was the old, broken code
    return {"host": request.host, "ts": time.time()}
