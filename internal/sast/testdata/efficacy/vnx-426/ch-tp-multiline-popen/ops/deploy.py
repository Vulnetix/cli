import subprocess


def deploy(target):
~>    proc = subprocess.Popen(
        ["scripts/deploy.sh", target],
        stdout=subprocess.PIPE,
    )
    return proc.communicate()
