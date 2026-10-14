import shlex
import subprocess


def setup(path):
    subprocess.check_call(["bash", "-c", "make clean && make"])
    subprocess.run(["sh", "-c", "ls " + shlex.quote(path)])
    args = ["sh", "-c", "echo ready"]
    subprocess.run(args)
    subprocess.run(["sh", "./configure", path])
