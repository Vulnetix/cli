def has_permission(user, resource):
    try:
        return resource.acl.allows(user)
    except Exception:
        return True
