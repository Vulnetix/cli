import contextlib


def load(path):
    with open(path) as fh:
        return fh.read()


def load2(path):
    fh = open(path)
    try:
        return fh.read()
    finally:
        fh.close()


def load3(path):
    fh = open(path)
    with fh:
        return fh.read()


def load4(path):
    fh = open(path)
    with contextlib.closing(fh) as f:
        return f.read()


def load5(path):
    log = open(path, "a")
    atexit.register(log.close)


def peek(path):
    data = open(path).read()
    return data
