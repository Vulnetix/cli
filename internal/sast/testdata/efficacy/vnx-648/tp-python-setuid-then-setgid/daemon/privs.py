import os
import pwd


def drop_privileges(user="nobody"):
    pw = pwd.getpwnam(user)
    os.setgroups([])
~>    os.setuid(pw.pw_uid)
    os.setgid(pw.pw_gid)
    os.umask(0o077)
