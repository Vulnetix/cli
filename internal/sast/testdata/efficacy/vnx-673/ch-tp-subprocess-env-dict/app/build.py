import os
import subprocess
from flask import request


def build():
    env = os.environ.copy()
~>    env["LD_LIBRARY_PATH"] = request.form["libdir"]
    subprocess.run(["make"], env=env, check=True)
