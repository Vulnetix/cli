from cachetools import TTLCache, cached

_perm_cache = TTLCache(maxsize=1024, ttl=30)


@cached(_perm_cache)
def has_permission(user_id, perm):
    return Grant.objects.filter(user_id=user_id, perm=perm).exists()


def is_admin(user_id):
    # previously @lru_cache, removed so revocation takes effect
    return User.objects.get(pk=user_id).is_superuser
