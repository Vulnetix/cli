import subprocess

from flask import request


def show():
    filename = request.args.get("file")
~>    out = subprocess.run(f"cat {filename}", shell=True, capture_output=True)
    return out.stdout
