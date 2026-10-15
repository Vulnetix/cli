import os
import pwd


def run_jailed(root, user, argv):
    entry = pwd.getpwnam(user)
    os.chroot(root)
    os.chdir("/")
    os.setgroups([])
    os.setresgid(entry.pw_gid, entry.pw_gid, entry.pw_gid)
    os.setresuid(entry.pw_uid, entry.pw_uid, entry.pw_uid)
    os.execv(argv[0], argv)
