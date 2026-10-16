from functools import lru_cache

ROLE_LABELS = {"admin": "Administrator", "editor": "Editor"}


@lru_cache(maxsize=None)
def get_role_display_name(role):
    return ROLE_LABELS.get(role, role.title())


@lru_cache(maxsize=None)
def get_permission_choices():
    return [("read", "Read"), ("write", "Write")]


@lru_cache(maxsize=None)
def can_parse(content_type):
    return content_type in {"application/json", "text/csv"}
