import os


def enter_jail(root):
    os.chroot(root)
    os.chdir("/")
    os.setuid(65534)
