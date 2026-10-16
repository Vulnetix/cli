import os
import subprocess


def run_user_job(uid, gid, cmd):
    return subprocess.run(cmd, user=uid, group=gid, extra_groups=[], check=True)


def run_full_drop(uid, cmd):
    os.setresuid(uid, uid, uid)
    os.execvp(cmd[0], cmd)


def peek(uid):
    # os.seteuid(uid) then subprocess.run(...) would be the bug
    return "seteuid then exec"
