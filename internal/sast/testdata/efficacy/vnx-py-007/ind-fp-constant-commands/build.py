import subprocess

CLEAN = "make clean"


def build():
    subprocess.run("make clean", shell=True)
    cmd = "tar czf out.tgz build/"
    subprocess.check_call(cmd, shell=True)
    subprocess.run(CLEAN, shell=True, check=True)
