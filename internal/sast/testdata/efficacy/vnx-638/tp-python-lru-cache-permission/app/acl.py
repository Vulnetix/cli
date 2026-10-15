import functools
from functools import lru_cache, cache


~>@lru_cache(maxsize=None)
def has_permission(user_id, perm):
    return Grant.objects.filter(user_id=user_id, perm=perm).exists()


~>@functools.lru_cache
def is_admin(user_id):
    return User.objects.get(pk=user_id).is_superuser


~>@cache
def get_user_roles(user_id):
    return set(Role.objects.filter(members=user_id).values_list("name", flat=True))


class Policy:
~>    @functools.cache
    def can_edit(self, user_id, doc_id):
        return self.engine.allowed(user_id, "edit", doc_id)
