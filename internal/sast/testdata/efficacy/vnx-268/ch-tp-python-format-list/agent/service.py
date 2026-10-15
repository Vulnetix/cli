import subprocess


def restart(service):
    cmd = ["sudo", "systemctl", "restart", service]
~>    subprocess.run(cmd, check=True)


def purge(path):
    command = "sudo rm -rf {}".format(path)
~>    return subprocess.call(command, shell=True)


def as_user(user, script):
~>    subprocess.check_call(
        ["sudo", "-u", user, "/bin/sh", script],
    )
