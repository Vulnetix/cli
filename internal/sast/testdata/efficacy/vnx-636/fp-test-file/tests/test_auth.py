def has_permission(user, resource):
    try:
        return resource.allows(user)
    except Exception:
        return True
