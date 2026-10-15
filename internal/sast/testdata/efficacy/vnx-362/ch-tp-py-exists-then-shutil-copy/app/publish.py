import os
import shutil


def publish(src, dest):
    if os.path.exists(dest):
        raise FileExistsError(dest)
~>    shutil.copyfile(src, dest)
