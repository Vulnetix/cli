import os
from os import chroot, chdir


def enter(jail):
    os.chroot(jail)
    os.chdir("/")


def enter2(jail):
    chroot(jail)
    chdir("/")
