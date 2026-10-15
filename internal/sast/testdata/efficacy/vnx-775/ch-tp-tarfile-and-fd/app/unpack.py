import os
import tarfile


def extract(archive, dest):
~>    tf = tarfile.open(archive)
    tf.extractall(dest, filter="data")
    return dest


async def head(path):
~>    fd = os.open(path, os.O_RDONLY)
    data = os.read(fd, 512)
    return data


def first_line(p):
~>    fh = p.open("r", encoding="utf-8")
    return fh.readline()
