import subprocess as sp

from flask import request


def restart():
    service = request.args["service"]
~>    sp.run(["sudo", "systemctl", "restart", service], check=True)


def run_helper(helper_path, arg):
~>    sp.call(["pkexec", helper_path, arg])
