import os


def enter(jail):
~>    os.chroot(jail)
    os.setgid(65534)
    os.setuid(65534)
    run_untrusted()
