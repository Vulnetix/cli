import os


def drop(uid, gid, name):
    os.setgroups([])
    os.initgroups(name, gid)
    os.setgid(gid)
    os.setuid(uid)


def regain():
    os.setuid(0)
    os.setgid(0)
