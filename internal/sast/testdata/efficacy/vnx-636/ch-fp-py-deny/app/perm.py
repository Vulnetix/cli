def has_permission(user, perm):
    try:
        return backend.check(user, perm)
    except Exception:
        log.exception("permission check failed")
        return False


def file_is_cached(path):
    try:
        os.stat(path)
    except OSError:
        return True
    return False
