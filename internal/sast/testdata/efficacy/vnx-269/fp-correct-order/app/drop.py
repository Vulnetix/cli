import os


def drop(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
