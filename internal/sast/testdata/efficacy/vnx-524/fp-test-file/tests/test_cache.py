from functools import lru_cache


@lru_cache
def fake_login(username, password):
    return True
