from cachetools import TTLCache, cached

_perm_cache = TTLCache(maxsize=1024, ttl=30)


@cached(_perm_cache)
def has_permission(user_id, perm):
    return Grant.objects.filter(user_id=user_id, perm=perm).exists()
