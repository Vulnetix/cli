import random

COLORS = ["red", "green", "blue"]


def pick_banner(user):
    color = random.choice(COLORS)
    delay = random.uniform(0.1, 0.5)
    sample = random.sample(range(100), 10)
    random.shuffle(sample)
    user.token_count = len(sample)
    return color, delay, sample
