import os
import subprocess


def run_user_job(uid, cmd):
    os.seteuid(uid)
~>    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    return out


def run_editor(uid, path):
    os.seteuid(uid)
~>    os.system("vi " + path)
