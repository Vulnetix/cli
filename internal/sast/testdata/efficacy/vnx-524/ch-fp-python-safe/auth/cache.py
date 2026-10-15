from functools import lru_cache

from django.core.cache import cache


@lru_cache(maxsize=64)
def get_user(user_id):
    return User.objects.get(pk=user_id)


def store(user, password_hash, token):
    cache.set(f"hash:{user.id}", password_hash)
    cache.set(f"reset:{user.id}", token, 3600)
    cache.set("password_policy", {"min_length": 12})
    cache.set(f"password_reset_sent:{user.id}", True)
    # cache.set("pw", password)
