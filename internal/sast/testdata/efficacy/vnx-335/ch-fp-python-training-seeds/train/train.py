import random

import numpy as np

SEED = 42


def setup():
    random.seed(SEED)
    np.random.seed(SEED)


def split(rows):
    random.shuffle(rows)
    cut = int(len(rows) * 0.8)
    tokens = [r["text"].split() for r in rows]
    return rows[:cut], rows[cut:], tokens
