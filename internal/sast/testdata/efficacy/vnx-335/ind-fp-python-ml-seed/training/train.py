import random

import numpy as np
import torch

SEED = 42


def set_seed():
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)


def split(rows):
    set_seed()
    random.shuffle(rows)
    cut = int(len(rows) * 0.8)
    return rows[:cut], rows[cut:]
