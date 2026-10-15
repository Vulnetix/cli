import os

ROOT = os.path.realpath("/var/www/static")


def resolve(path):
    full = os.path.realpath(os.path.join(ROOT, path))
    if not full.startswith(ROOT + os.sep):
        return None
    if not (full + "/").startswith(os.path.join(ROOT, "")):
        return None
    return full


def is_temp(name):
    return name.startswith("tmp")
