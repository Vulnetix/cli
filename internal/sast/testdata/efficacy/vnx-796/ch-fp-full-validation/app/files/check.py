import os
import re

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def checked(base, name):
    if not SAFE_NAME.match(name) or ".." in name:
        raise ValueError(name)
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(os.path.realpath(base) + os.sep):
        raise ValueError(name)
    return full
