import random


def schedule(last_poll):
    next_poll = last_poll + random.randint(1, 5)
    return next_poll


def wander(prev_x, prev_y):
    x = prev_x + random.randint(-2, 2)
    y = prev_y + random.randint(-2, 2)
    return x, y
