import os
from urllib.parse import unquote

from flask import abort, request, send_file


def report():
    name = request.args.get("name", "")
~>    if ".." in name or name.startswith("/"):
        abort(400)
    path = os.path.join("/srv/reports", unquote(name))
    return send_file(path)
