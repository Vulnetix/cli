import random

from app.keys import generate_api_key


def test_api_key_length():
    random.seed(random.randint(0, 99))
    api_key = generate_api_key()
    assert len(api_key) == 32
