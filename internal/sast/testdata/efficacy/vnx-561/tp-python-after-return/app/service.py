def load(path):
    with open(path) as fh:
        data = fh.read()
    return data
~>    log.info("loaded %s", path)


def check(user):
    if user.is_admin:
        return True
~>        audit(user)
    return False
