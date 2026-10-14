import os


def current_umask():
    current = os.umask(0)
    os.umask(current)
    return current


def harden():
    os.umask(0o077)
    os.umask(0o022)
    # os.umask(0) would let every file be created world-writable
