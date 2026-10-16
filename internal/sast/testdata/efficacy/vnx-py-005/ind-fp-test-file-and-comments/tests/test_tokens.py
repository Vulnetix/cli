import random


def test_fake_password():
    password = str(random.randint(1000, 9999))
    token = random.random()
    # token = random.random() is weak in production
    assert password and token
