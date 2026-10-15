import random
import time


def test_reset_token_shape():
    random.seed(time.time())
    reset_token = random.getrandbits(64)
    assert reset_token >= 0
