import os
import pwd

def drop_privileges(name):
    pw = pwd.getpwnam(name)
~>    os.setuid(pw.pw_uid)
    os.setgid(pw.pw_gid)
