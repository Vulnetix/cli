import functools

from app.models import Grant


~>@functools.lru_cache(maxsize=None)
def has_permission(user_id, perm):
    return Grant.objects.filter(user_id=user_id, perm=perm).exists()
