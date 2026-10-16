import re
from flask import abort, request


def check_username():
    name = request.args.get("user", "")
~>    if not re.match(r"[a-zA-Z0-9_]+", name):
        abort(400)
    return name
