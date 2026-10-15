import os

BASE = os.path.realpath("/srv/data") + os.sep
PREFIX = "/srv/cache/"


def check(rel):
    full = os.path.realpath(os.path.join(BASE, rel))
    if not full.startswith(BASE):
        raise ValueError(rel)
    cached = os.path.abspath(rel)
    return cached.startswith(PREFIX)
