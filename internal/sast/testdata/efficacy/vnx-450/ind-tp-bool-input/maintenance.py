import shutil


def rotate_storage(path):
~>    keep_backup = bool(input("Keep a backup of the old store? [y/N] "))
    if keep_backup:
        shutil.copytree(path, path + ".bak")
    shutil.rmtree(path)
