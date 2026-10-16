import os


def rotate(path):
    f = open(path, "a")
    f.write("x")
    f.close()
    f = open(path + ".1", "a")
    f.write("y")
    f.close()


def early(path, ok):
    f = open(path)
    if not ok:
        f.close()
        return None
    return f.read()


def checked(f):
    f.close()
    return f.closed


def inside(path):
    with open(path) as fh:
        data = fh.read()
        fh.seek(0)
    return data
