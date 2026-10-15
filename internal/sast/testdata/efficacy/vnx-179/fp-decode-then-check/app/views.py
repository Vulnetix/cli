import os
from urllib.parse import unquote

from flask import abort, request, send_file


def report():
    name = unquote(request.args.get("name", ""))
    if ".." in name or name.startswith("/"):
        abort(400)
    return send_file(os.path.join("/srv/reports", name))


def report_two():
    raw = request.args.get("name", "")
    if "%" in raw:
        abort(400)
    name = unquote(raw)
    return send_file(os.path.join("/srv/reports", name))
