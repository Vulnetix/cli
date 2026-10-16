import os
import subprocess


def build(target):
    env = os.environ.copy()
~>    env["LD_LIBRARY_PATH"] = "lib:" + env.get("LD_LIBRARY_PATH", "")
~>    os.putenv("PYTHONPATH", "./src")
~>    os.environ["PATH"] = os.environ["PATH"] + os.pathsep + "."
    subprocess.check_call(["/usr/bin/make", target], env=env)
