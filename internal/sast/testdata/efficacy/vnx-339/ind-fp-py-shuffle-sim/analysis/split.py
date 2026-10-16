import random


def train_test_split(rows, ratio=0.8):
    random.seed(len(rows) % 1000)
    shuffled = rows[:]
    random.shuffle(shuffled)
    cut = int(len(shuffled) * ratio)
    return shuffled[:cut], shuffled[cut:]
