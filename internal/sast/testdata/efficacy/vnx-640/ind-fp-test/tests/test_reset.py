import random

def test_token():
    reset_token = str(random.randint(100000, 999999))
    assert reset_token
