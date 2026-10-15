import subprocess
import os


def add_user(name):
    cmd = f"sudo useradd -m {name}"
~>    subprocess.run(cmd, shell=True, check=True)


def mount(device):
    command = "sudo mount {} /mnt/data".format(device)
~>    os.system(command)
