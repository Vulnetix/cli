def has_permission(user, resource):
    try:
        return resource.acl.allows(user)
    except Exception:
        return False


def verify_signature(key, payload, sig):
    try:
        key.verify(sig, payload)
    except InvalidSignature:
        return False
    return True


def is_authorized(request):
    try:
        check(request)
    except Denied:
        raise PermissionError("denied")
    return True
