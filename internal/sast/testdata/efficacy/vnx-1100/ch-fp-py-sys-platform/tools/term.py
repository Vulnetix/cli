import os
import subprocess
import sys


def clear():
    if sys.platform.startswith("win"):
        os.system("cls")
    else:
        os.system("clear")


def shell(cmd):
    if os.name == "nt":
        return subprocess.run(["cmd", "/c", cmd])
    return subprocess.run(["/bin/sh", "-c", cmd])
