import shlex
import subprocess


def a(name):
    subprocess.run(["cat", name], check=True)


def b(name):
    subprocess.run(f"cat {shlex.quote(name)}", shell=True)


def c(name):
    cmd = "grep -r " + shlex.quote(name) + " ."
    subprocess.check_output(cmd, shell=True)


def d(name):
    subprocess.run(f"cat {name}", shell=False)
    # subprocess.run(cmd, shell=True) is dangerous
    return "shell=True"
