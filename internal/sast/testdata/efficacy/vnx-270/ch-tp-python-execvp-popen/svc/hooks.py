import os
import subprocess


def run_hook(uid, prog, args):
    os.seteuid(uid)
~>    os.execvp(prog, [prog, *args])


def spawn(uid, cmd):
    os.seteuid(uid)
    log_line = "spawning"
~>    return subprocess.Popen(cmd)
