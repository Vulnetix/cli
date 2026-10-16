import gzip
import os


def count_lines(p):
~>    g = gzip.open(p, "rt")
    n = 0
    for _ in g:
        n += 1
    return n


def lock(path):
~>    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    os.write(fd, b"1")
