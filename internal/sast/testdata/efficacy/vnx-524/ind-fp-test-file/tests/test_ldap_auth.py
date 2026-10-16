import functools

from django.core.cache import cache


@functools.lru_cache(maxsize=None)
def fake_check(username, password):
    return password == "hunter2"


def test_signup_cache_roundtrip():
    password = "correct horse"
    cache.set("signup:abc", password, timeout=5)
    assert cache.get("signup:abc") == password
    assert fake_check("bob", "hunter2")
