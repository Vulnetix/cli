import os
from pathlib import Path

ROOT = "/srv/uploads"


def a(name):
    target = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, target]) != ROOT:
        raise PermissionError(name)


def b(name):
    target = os.path.realpath(os.path.join(ROOT, name))
    if not target.startswith(ROOT + os.sep):
        raise PermissionError(name)


def c(name):
    return Path(name).resolve().is_relative_to(ROOT)
