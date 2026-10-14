import os


def create_exact(path):
    previous = os.umask(0)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    finally:
        os.umask(previous)
    return fd
