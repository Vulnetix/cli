import os

from flask import abort, request


def outbound():
    target = request.args.get("url", "")
    if not target.startswith("https://"):
        abort(400)
    return {"redirect": target}


def is_absolute(p):
    joined = os.path.join(os.getcwd(), p)
    return joined.startswith("/")
