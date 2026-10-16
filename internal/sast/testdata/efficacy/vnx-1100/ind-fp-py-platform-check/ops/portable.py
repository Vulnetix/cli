import os
import subprocess
import sys


def clear_screen():
    if sys.platform.startswith("win"):
        os.system("cls")
    else:
        os.system("clear")


def run(script):
    if os.name == "nt":
        subprocess.run(["cmd", "/c", script])
    else:
        subprocess.run(["/bin/sh", "-c", script])
