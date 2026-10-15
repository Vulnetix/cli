import os


def reset_link(p, target):
    if os.path.islink(p):
        old = os.readlink(p)
        os.unlink(p)
        print("removed link to", old)
    os.symlink(target, p)
