import os
import subprocess


def build():
~>    env = dict(os.environ, PATH="node_modules/.bin:" + os.environ["PATH"])
    subprocess.run(["/usr/bin/make", "all"], env=env, check=True)
~>    os.environ["LD_LIBRARY_PATH"] = os.environ.get("LD_LIBRARY_PATH", "") + ":"
