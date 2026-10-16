import os
import shutil
import stat


def _on_error(func, path, exc_info):
    os.chmod(path, 0o777)
    func(path)


def wipe(tree):
    shutil.rmtree(tree, onerror=_on_error)


def make_private(path):
    mode = os.stat(path).st_mode
    os.chmod(path, mode & ~stat.S_IWOTH)
