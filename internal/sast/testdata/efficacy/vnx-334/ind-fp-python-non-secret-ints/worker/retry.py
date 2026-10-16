import random
import time


def backoff(attempt: int) -> None:
    delay = random.randint(1, 5) * attempt
    time.sleep(delay)


def pick_port() -> int:
    port = random.randint(20000, 30000)
    return port


def roll() -> int:
    dice = random.randint(1, 6)
    return dice
