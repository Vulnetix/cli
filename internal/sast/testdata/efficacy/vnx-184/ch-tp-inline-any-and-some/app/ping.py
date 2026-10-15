import subprocess

from flask import abort, request


def ping():
    host = request.args.get("host", "")
~>    if any(c in host for c in [";", "&", "|", "`", "$("]):
        abort(400)
    return subprocess.check_output("ping -c 1 " + host, shell=True)
