import os
import subprocess


def run_job(uid, cmd):
    os.seteuid(uid)
~>    subprocess.run(cmd, check=True)


def open_shell(uid):
    os.setegid(1000)
    os.seteuid(uid)
~>    os.execvp("bash", ["bash", "-l"])
