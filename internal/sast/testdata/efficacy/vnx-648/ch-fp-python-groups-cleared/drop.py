import grp
import os
import pwd


def drop_privileges(user="www-data"):
    if os.getuid() != 0:
        return
    pw = pwd.getpwnam(user)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.umask(0o077)
