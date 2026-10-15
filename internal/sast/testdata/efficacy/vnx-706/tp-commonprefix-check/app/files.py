import os
from os.path import commonprefix

UPLOAD_ROOT = "/srv/uploads"


def resolve(name):
    target = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
~>    if os.path.commonprefix([UPLOAD_ROOT, target]) != UPLOAD_ROOT:
        raise PermissionError(name)
    return target


def inside(base, path):
~>    return commonprefix((base, os.path.abspath(path))) == base
