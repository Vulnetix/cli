import os
import pwd


def drop_to(username):
    pw = pwd.getpwnam(username)
    os.setgroups([])
~>    os.setuid(pw.pw_uid)
    os.setgid(pw.pw_gid)
    os.umask(0o077)
