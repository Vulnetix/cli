import os


def shared_stem(names):
    stem = os.path.commonprefix(names)
    return stem.rstrip("_-")


def label(p):
    name = os.path.basename(os.path.realpath(p))
    return name.startswith("tmp")
