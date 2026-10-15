import os
import subprocess


def read_as(uid, path):
    os.seteuid(uid)
    try:
        with open(path) as fh:
            data = fh.read()
    finally:
        os.seteuid(0)
    subprocess.run(["/usr/bin/logger", "read done"])
    return data


def run_dropped(uid, gid, cmd):
    os.setgid(gid)
    os.setuid(uid)
    subprocess.run(cmd)
