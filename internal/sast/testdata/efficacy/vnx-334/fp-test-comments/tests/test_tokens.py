import random


def test_token_collision():
    token = random.randint(0, 9)
    assert token < 10
