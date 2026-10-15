import os
import subprocess


def prepare():
~>    os.environ["PATH"] += os.pathsep + "."
~>    os.environ["LD_LIBRARY_PATH"] += ":"
~>    os.environ['PYTHONPATH'] += ":" + "vendor"
    subprocess.run(["/usr/bin/env"], check=True)
