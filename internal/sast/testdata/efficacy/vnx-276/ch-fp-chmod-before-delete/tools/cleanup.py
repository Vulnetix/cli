import os
import shutil
import stat


def _make_writable_and_retry(func, path, _exc_info):
    os.chmod(path, 0o777)
    func(path)


def remove_tree(root):
    shutil.rmtree(root, onerror=_make_writable_and_retry)


def remove_file(path):
    os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    os.remove(path)
