import os
import stat


def publish(path):
    os.chmod(path, 0o755)
    os.chmod(path + ".sig", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)


def check(path):
    if os.stat(path).st_mode & stat.S_ISUID:
        raise RuntimeError("refusing set-uid file")
    if os.getuid() == 0:
        os.setuid(1000)
