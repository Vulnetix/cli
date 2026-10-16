import functools
from functools import lru_cache

from .models import Grant, Membership


~>@lru_cache(maxsize=None)
def has_permission(user_id, perm):
    return Grant.objects.filter(user_id=user_id, perm=perm).exists()


~>@functools.lru_cache(maxsize=4096)
def is_admin(user_id):
    return Membership.objects.filter(user_id=user_id, role="admin").exists()
