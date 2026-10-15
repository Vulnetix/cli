import os
import pwd


def run_as(user):
    pw = pwd.getpwnam(user)
    os.setgid(pw.pw_gid)
~>    os.setuid(pw.pw_uid)
    serve_forever()
