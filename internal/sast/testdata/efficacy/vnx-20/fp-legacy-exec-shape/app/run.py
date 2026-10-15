import subprocess

from flask import request


def run():
    # command execution is reported by the injection rules, not by VNX-20
    subprocess.run(["echo", request.args.get("msg", "")], check=True)
    return "ok"
