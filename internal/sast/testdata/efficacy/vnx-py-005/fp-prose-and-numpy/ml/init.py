# never use random.choice() for a password; use secrets
import numpy as np

HELP = "token = random.randint(0, 9) is predictable"


def init_weights(shape, seed_token):
    rng = np.random.default_rng(42)
    noise = np.random.randint(0, 10, size=shape)
    return rng.normal(size=shape) + noise
