import os


def current_umask():
    old = os.umask(0)
    os.umask(old)
    return old
