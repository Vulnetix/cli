import random
import time

random.seed(time.time())


def sample_rows(rows):
    return random.sample(rows, 20)
