import os
import tarfile


def unpack_all(src, dest):
    names = sorted(os.listdir(src))
    for name in names:
        if name.startswith("."):
            continue
        with tarfile.open(os.path.join(src, name)) as t:
~>            t.extractall(dest)
