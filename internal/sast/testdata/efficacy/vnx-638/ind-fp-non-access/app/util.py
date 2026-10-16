import functools
from django.utils.functional import cached_property


@functools.lru_cache(maxsize=128)
def parse_version(s):
    return tuple(int(x) for x in s.split("."))


@functools.lru_cache
def get_role_display_name(role):
    return role.title()


@functools.lru_cache
def get_permission_choices():
    return [("r", "read"), ("w", "write")]


class Req:
    @cached_property
    def is_admin(self):
        return self.user.is_staff
