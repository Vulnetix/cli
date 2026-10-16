from functools import cached_property, lru_cache

from cachetools import TTLCache, cached

from .models import Grant

_perm_cache = TTLCache(maxsize=1024, ttl=30)


@cached(_perm_cache)
def has_permission(user_id, perm):
    return Grant.objects.filter(user_id=user_id, perm=perm).exists()


class RequestContext:
    def __init__(self, user):
        self.user = user

    @cached_property
    def is_admin(self):
        return self.user.groups.filter(name="admin").exists()


@lru_cache(maxsize=256)
def parse_version(v):
    return tuple(int(x) for x in v.split("."))
