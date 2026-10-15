import os


def make_fifo(path):
    os.umask(0)
    os.mkfifo(path, 0o620)
    os.umask(0o022)
