import os

UPLOAD_ROOT = "/srv/uploads"


def save(name, data):
    target = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
~>    if os.path.commonprefix([UPLOAD_ROOT, target]) != UPLOAD_ROOT:
        raise PermissionError(name)
    with open(target, "wb") as fh:
        fh.write(data)
