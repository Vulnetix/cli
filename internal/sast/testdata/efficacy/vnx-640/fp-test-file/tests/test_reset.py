import random


def test_reset():
    reset_token = str(random.randint(100000, 999999))
    assert reset_token
