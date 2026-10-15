import os

ROOT = "/srv/uploads"


def resolve(name):
    target = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, target]) != ROOT:
        raise PermissionError(name)
    if not target.startswith(ROOT + os.sep):
        raise PermissionError(name)
    if not os.path.realpath(name).startswith(os.path.join(ROOT, "")):
        raise PermissionError(name)
    if not os.path.abspath(name).startswith("/srv/uploads/"):
        raise PermissionError(name)
    return target
