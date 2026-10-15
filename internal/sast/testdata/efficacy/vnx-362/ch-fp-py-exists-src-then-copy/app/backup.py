import os
import shutil
import tempfile


def backup(src):
    if not os.path.isfile(src):
        return None
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    shutil.copy2(src, tmp)
    return tmp
