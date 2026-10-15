from functools import lru_cache, cache


@lru_cache
def get_role_display_name(role):
    return ROLE_LABELS.get(role, role)


@cache
def can_parse(fmt):
    return fmt in PARSERS


@lru_cache(maxsize=None)
def get_permission_choices():
    return [(p.code, p.label) for p in PERMISSIONS]
