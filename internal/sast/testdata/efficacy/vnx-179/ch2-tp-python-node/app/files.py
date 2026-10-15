from urllib.parse import unquote
from flask import abort, request, send_file


def download():
    name = request.args.get("name", "")
~>    if ".." in name:
        abort(400)
    name = unquote(name)
    return send_file("/srv/files/" + name)
