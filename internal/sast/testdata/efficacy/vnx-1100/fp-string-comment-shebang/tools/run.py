#!/bin/bash
import shutil
import subprocess

HELP = "run with: bash -c ./deploy.sh"


def deploy(path):
    # subprocess.run(["/bin/bash", "-c", path]) is not portable
    subprocess.run(["tar", "czf", "out.tgz", path], check=True)
    subprocess.run("echo done", shell=True)
    return shutil.which("bash")
