import os
import shutil
import subprocess


def build(target):
    env = dict(os.environ, SHELL="/bin/bash")
    env2 = {"SHELL": "/bin/bash", "TERM": "dumb"}
    make = shutil.which("make")
    subprocess.run([make, target], env=env2, check=True)
    have_bash = shutil.which("bash") is not None
    return have_bash
