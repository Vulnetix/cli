import os
import subprocess


def run_job(uid, gid, cmd):
    os.setgid(gid)
    os.setuid(uid)
    subprocess.run(cmd, check=True)


def run_as(uid, cmd):
    subprocess.run(cmd, user=uid, check=True)
