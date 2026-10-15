import os
import stat
import pwd


def drop(name):
    pw = pwd.getpwnam(name)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def harden(path):
    os.chmod(path, 0o755)
    mode = os.stat(path).st_mode
    os.chmod(path, mode & ~stat.S_ISUID)
    return bool(mode & stat.S_ISUID)
