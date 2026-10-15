import subprocess

CLEAN_CMD = "rm -rf build dist *.egg-info"


def clean():
    subprocess.run(CLEAN_CMD, shell=True, check=True)
