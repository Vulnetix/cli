import os
import pwd


def drop(username):
    pw = pwd.getpwnam(username)
    os.setuid(pw.pw_uid)
~>    os.setgroups([])
~>    os.setgid(pw.pw_gid)
