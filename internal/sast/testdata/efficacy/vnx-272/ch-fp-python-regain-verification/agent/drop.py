import os


def drop(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    try:
        os.seteuid(0)
    except PermissionError:
        pass
    else:
        raise RuntimeError("root could be regained after dropping")
