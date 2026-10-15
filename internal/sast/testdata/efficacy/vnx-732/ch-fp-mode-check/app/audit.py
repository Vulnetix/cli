import os
import stat


def is_world_writable(path):
    mode = os.stat(path).st_mode
    if mode & stat.S_IWOTH:
        print("chmod 0o777 is too open:", path)
        return True
    return False
