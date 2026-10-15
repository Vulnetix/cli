import random

random.seed(42)


def estimate_pi(n):
    inside = 0
    for _ in range(n):
        x, y = random.random(), random.random()
        if x * x + y * y <= 1:
            inside += 1
    return 4 * inside / n


def pick_sample(rows):
    return random.sample(rows, 10)
