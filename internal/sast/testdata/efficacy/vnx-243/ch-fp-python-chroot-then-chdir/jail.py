import os


def enter(path):
    os.chroot(path)
    os.chdir("/")
    os.setuid(65534)
