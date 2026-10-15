import os


def create(path, data):
    if os.path.exists(path):
        return False
    with open(path, "x") as fh:
        fh.write(data)
    fd = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.close(fd)
    return True


def create2(path):
    if not os.path.exists(path):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
