import os
import pwd

def drop(name):
    pw = pwd.getpwnam(name)
    os.initgroups(name, pw.pw_gid)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
