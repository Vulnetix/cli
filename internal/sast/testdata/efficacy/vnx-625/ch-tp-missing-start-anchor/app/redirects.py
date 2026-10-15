import re
from flask import abort, redirect, request


def safe_next():
    target = request.args.get("next", "/")
~>    if re.search(r"example\.com$", target):
        return redirect(target)
    abort(400)


def trusted_host(hostname):
~>    return re.search(r"corp\.internal$", hostname) is not None
