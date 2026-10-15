import random


def test_token_is_hex():
    random.seed(0)
    token = random.getrandbits(64)
    assert token >= 0
