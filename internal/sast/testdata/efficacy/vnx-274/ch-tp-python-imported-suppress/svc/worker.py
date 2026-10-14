import os
from contextlib import suppress


def drop(uid, gid):
    with suppress(PermissionError):
~>        os.setgid(gid)
~>        os.setuid(uid)
    return uid
