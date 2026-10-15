from functools import lru_cache
from django.core.cache import cache


@lru_cache(maxsize=256)
def get_user(user_id: int):
    return User.objects.get(pk=user_id)


@lru_cache
def password_policy(locale):
    return load_policy(locale)


def store(user, password_hash, token):
    cache.set(f"hash:{user}", password_hash)
    cache.set(f"tok:{user}", token, timeout=60)
    cache.set("password_reset_sent", True)
    cache.set("msg", "password changed")
