import os
import pwd


def demote(username):
    # wrong order would be: os.setuid(...) then os.setgid(...)
    pw = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    msg = "os.setuid(uid); os.setgid(gid) is the classic bug"
    return msg
