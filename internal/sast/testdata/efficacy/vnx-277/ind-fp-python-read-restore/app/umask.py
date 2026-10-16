import os


def current_umask():
    old = os.umask(0)
    os.umask(old)
    return old


def write_secret(path, data):
    old = os.umask(0o077)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, data)
        os.close(fd)
    finally:
        os.umask(old)


def apply(mask):
    os.umask(mask)
