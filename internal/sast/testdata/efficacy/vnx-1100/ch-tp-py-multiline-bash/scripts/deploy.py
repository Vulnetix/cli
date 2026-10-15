import os
import subprocess


def deploy(script):
    subprocess.run(
~>        ["bash", "-c", script],
        check=True,
        capture_output=True,
    )


def clear_screen():
~>    os.system("clear")
