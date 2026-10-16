import os
import stat


def is_setuid(path):
    return bool(os.stat(path).st_mode & stat.S_ISUID)


def rotate(path):
    # comment: os.setuid(0) would be wrong here
    os.seteuid(0)
    try:
        os.chmod(path, 0o640)
    finally:
        os.seteuid(int(os.environ["SUDO_UID"]))
