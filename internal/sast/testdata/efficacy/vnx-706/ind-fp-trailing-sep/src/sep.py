import os

BASE = os.path.join("/srv/data", "")
PUB = "/srv/pub/"


def a(name):
    t = os.path.realpath(os.path.join(BASE, name))
    return t.startswith(BASE)


def b(name):
    t = os.path.abspath(name)
    return t.startswith("/srv/pub/")


def c(name):
    t = os.path.realpath(name)
    return t.startswith(PUB)
