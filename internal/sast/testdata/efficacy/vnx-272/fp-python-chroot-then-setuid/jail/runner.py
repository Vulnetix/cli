import os
import pwd


def enter(jail_dir, user):
    entry = pwd.getpwnam(user)
    os.chroot(jail_dir)
    os.chdir("/")
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
