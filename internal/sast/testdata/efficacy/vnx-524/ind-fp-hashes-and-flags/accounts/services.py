import functools

from django.contrib.auth.hashers import make_password
from django.core.cache import cache


@functools.lru_cache(maxsize=128)
def password_policy(org_id: int) -> dict:
    return {"min_length": 12, "org": org_id}


@functools.lru_cache(maxsize=512)
def user_permissions(user_id: int) -> frozenset:
    return frozenset()


def start_reset(user, raw_password):
    password_hash = make_password(raw_password)
    cache.set(f"pending-hash:{user.pk}", password_hash, timeout=600)
    cache.set(f"password_reset_sent:{user.pk}", True, timeout=3600)
    cache.set(f"user:{user.pk}:pw", user.password, timeout=60)
    cache.set(f"session:{user.pk}", user.session_token, timeout=60)
    # cache.set(f"signup:{user.pk}", password)  -- never do this
