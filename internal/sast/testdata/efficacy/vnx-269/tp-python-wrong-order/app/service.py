import os
import pwd


def drop(name):
    pw = pwd.getpwnam(name)
    os.setuid(pw.pw_uid)
~>    os.setgid(pw.pw_gid)
~>    os.setgroups([])


class Worker:
    def demote(self, uid, gid):
        os.setresuid(uid, uid, uid)
~>        os.initgroups(self.user, gid)
