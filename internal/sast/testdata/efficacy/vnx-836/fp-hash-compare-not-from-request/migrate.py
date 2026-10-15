def migrate(old, new):
    if old.password_hash != new.password_hash:
        new.password_changed_at = now()


def same(request, a, b):
    log(request.path)
    return a.passwordHash == b.passwordHash
