import os
import shutil


def publish(src, dst):
    shutil.copy(src, dst)
    os.chmod(dst, 0o777)
    os.chmod(os.path.dirname(dst), 0o755)
