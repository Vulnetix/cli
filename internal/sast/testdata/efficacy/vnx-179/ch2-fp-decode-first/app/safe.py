from urllib.parse import unquote
from flask import abort, request


def download():
    name = unquote(request.args.get("name", ""))
    if ".." in name or name.startswith("/"):
        abort(400)
    return name


def label(value):
    if "<script" in value:
        raise ValueError("no")
    return html_escape(value)
