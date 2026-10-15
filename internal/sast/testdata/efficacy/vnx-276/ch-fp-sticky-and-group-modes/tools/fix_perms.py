import os
import stat


def lock_down(path):
    mode = os.stat(path).st_mode
    os.chmod(path, mode & ~stat.S_IWOTH)
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    os.makedirs("/tmp/work", mode=0o777, exist_ok=True)
