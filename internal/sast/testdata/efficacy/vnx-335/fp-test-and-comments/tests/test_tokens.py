import random

random.seed(0)


def test_token():
    token = random.choice("abc")
    assert token
