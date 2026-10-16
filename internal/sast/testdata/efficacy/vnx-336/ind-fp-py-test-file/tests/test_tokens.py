import random

from app.auth.tokens import generate_reset_token


def test_reset_token_is_deterministic_under_seed(user):
    random.seed(1337)
    first = generate_reset_token(user)
    random.seed(1337)
    assert generate_reset_token(user) == first
