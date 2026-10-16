from os import chroot, setuid


def confine(path):
~>    chroot(path)
    setuid(65534)
