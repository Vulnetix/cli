import random
import time
import numpy as np


def shuffle_deck(cards):
    random.shuffle(cards)
    colour = random.choice(["red", "green"])
    max_tokens = random.randint(100, 500)
    weights = np.random.random(10)
    return cards, colour, max_tokens, weights


def refresh_token():
    time.sleep(random.uniform(0, 1))
    return fetch()
