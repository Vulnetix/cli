import os


def enter(root):
~>    os.chroot(root)
    os.chdir("work")
    os.execv("/bin/app", ["app"])
