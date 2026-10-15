import os
from pathlib import Path

BASE = Path("/srv/uploads").resolve()


def safe(name):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise PermissionError(name)
    return target


def safe_str(name):
    full = os.path.realpath(os.path.join("/srv/uploads", name))
    if not full.startswith("/srv/uploads" + os.sep):
        raise PermissionError(name)
    return full


def label(name):
    tag = "img-" + name
    return tag.startswith("img-thumb")
