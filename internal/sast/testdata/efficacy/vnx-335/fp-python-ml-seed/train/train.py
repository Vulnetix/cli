import random
import numpy as np

random.seed(42)
np.random.seed(42)


def shuffle(data):
    random.shuffle(data)
    return data
