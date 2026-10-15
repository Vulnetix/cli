from random import choice, seed

COLOURS = ["red", "green", "blue"]


def simulate(n):
    seed(42)
    return [choice(COLOURS) for _ in range(n)]
