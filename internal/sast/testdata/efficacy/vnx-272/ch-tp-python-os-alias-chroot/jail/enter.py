import os as _os


def enter(root):
~>    _os.chroot(root)
    _os.chdir("/")
    return _os.getpid()
