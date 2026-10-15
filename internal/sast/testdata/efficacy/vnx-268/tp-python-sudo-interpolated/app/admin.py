import os
import subprocess


def restart(service):
~>    subprocess.run(["sudo", "systemctl", "restart", service], check=True)


def remove(path):
~>    os.system(f"sudo rm -rf {path}")


def chown(user, path):
~>    subprocess.call("sudo chown " + user + " " + path, shell=True)


def kill(pid):
~>    out = os.popen("sudo kill -9 %s" % pid).read()
    return out


def as_user(name, script):
~>    subprocess.Popen(
        ["/usr/bin/sudo", "-u", name, script],
        stdout=subprocess.PIPE,
    )


def as_doas(cmd):
~>    return subprocess.check_output(["doas", *cmd])
