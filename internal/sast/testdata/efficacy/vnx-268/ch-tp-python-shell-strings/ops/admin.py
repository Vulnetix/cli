import os
import subprocess


def chown(user, path):
~>    os.system(f"sudo chown {user} {path}")


def raw(cmd):
~>    return subprocess.check_output("sudo " + cmd, shell=True)


def as_user(user, script):
    cmd = "sudo -u %s %s" % (user, script)
~>    return os.popen(cmd).read()


def doas(tool, *args):
~>    subprocess.Popen(
        ["doas", tool, *args],
        stdout=subprocess.PIPE,
    )
