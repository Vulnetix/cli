import random

SEED = 1234
random.seed(SEED)


def shuffled(rows):
    return sorted(rows, key=lambda r: random.random())


def split(rows, ratio=0.8):
    rows = shuffled(rows)
    cut = int(len(rows) * ratio)
    return rows[:cut], rows[cut:]
