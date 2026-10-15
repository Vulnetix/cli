import os

BASE = "/srv/uploads"


def open_upload(name):
    target = os.path.realpath(os.path.join(BASE, name))
~>    if os.path.commonprefix([BASE, target]) != BASE:
        raise PermissionError(name)
    return open(target, "rb")
