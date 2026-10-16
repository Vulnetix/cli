import os
import pwd


def demote(username):
    pw = pwd.getpwnam(username)
    os.setuid(pw.pw_uid)
~>    os.initgroups(username, pw.pw_gid)
~>    os.setgid(pw.pw_gid)
    os.chdir(pw.pw_dir)
