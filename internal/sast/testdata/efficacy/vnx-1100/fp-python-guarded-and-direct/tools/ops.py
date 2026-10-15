import os
import subprocess
import sys


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def shell():
    if sys.platform.startswith("win"):
        return subprocess.run(["cmd", "/c", "ver"])
    return subprocess.run(["/bin/sh", "-c", "uname -a"])
