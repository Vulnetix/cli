from urllib.parse import unquote

from flask import abort, request


def page():
    name = request.args.get("name", "")
    if ".." in name or "%" in name:
        abort(400)
    return render(unquote(name))
