import subprocess
from flask import request


def show():
    filename = request.args.get("file")
~>    subprocess.run(f"cat {filename}", shell=True)
