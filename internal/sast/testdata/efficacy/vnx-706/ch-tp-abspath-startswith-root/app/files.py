import os

ROOT = "/var/www/static"


def resolve(path):
    full = os.path.abspath(os.path.join(ROOT, path))
~>    if not full.startswith(ROOT):
        return None
    return full
