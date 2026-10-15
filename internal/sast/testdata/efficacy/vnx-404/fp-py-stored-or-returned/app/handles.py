class Log:
    def __init__(self, path):
        self.fh = open(path, "a")

    def reopen(self, path):
        fh = open(path, "a")
        self.fh = fh


def open_log(path):
    fh = open(path, "a")
    return fh


def tail_files(paths):
    handles = []
    for p in paths:
        h = open(p)
        handles.append(h)
    return handles


def numbers(path):
    fh = open(path)
    yield from fh


cfg = open("settings.ini")
