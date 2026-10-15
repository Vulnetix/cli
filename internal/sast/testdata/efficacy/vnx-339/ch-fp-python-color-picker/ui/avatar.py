import random

PALETTE = ["#f00", "#0f0", "#00f", "#ff0"]


def avatar_colour(name):
    rng = random.Random(hash(name) % 1000)
    return rng.choice(PALETTE)
