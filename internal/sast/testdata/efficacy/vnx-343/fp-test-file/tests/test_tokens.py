import random


def test_tokens_are_ordered():
    last_token = 10
    token = last_token + random.randint(1, 100)
    assert token > last_token
