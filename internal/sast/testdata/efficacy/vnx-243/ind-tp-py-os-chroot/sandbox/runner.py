import os


def enter_jail(root, uid, gid):
~>    os.chroot(root)
    os.setgid(gid)
    os.setuid(uid)
    os.execv("/bin/worker", ["worker"])
