import subprocess
import os


def test_shell():
    subprocess.run(["/bin/bash", "-c", "true"], check=True)
    os.system("clear")
