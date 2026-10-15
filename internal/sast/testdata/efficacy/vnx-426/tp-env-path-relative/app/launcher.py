import os
import subprocess

~>os.environ["PATH"] = "." + os.pathsep + os.environ["PATH"]
~>os.environ['PATH'] = os.environ['PATH'] + ':'
~>os.environ["LD_LIBRARY_PATH"] = f"./lib:{os.environ.get('LD_LIBRARY_PATH', '')}"
~>os.putenv("PYTHONPATH", "plugins:/opt/app")


def run(cmd):
    env = dict(os.environ)
~>    env["PATH"] = "bin:" + env.get("PATH", "")
    return subprocess.run(cmd, env=env)
