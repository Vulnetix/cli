import os
import tempfile


def atomic_write(dest, data):
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(dest))
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp_path, dest)
