import os
import stat


def harden(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode & ~stat.S_IWOTH)
    os.chmod(path, 0o755)
    os.chmod(path, 0o640)
