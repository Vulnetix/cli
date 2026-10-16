import os


def same_dir(target):
    pwd = os.getcwd()
    if pwd == target:
        return True
    return pwd != os.path.realpath(target)
