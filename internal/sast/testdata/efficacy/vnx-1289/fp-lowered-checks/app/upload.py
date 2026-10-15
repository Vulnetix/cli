import os

from flask import abort, request


def upload():
    f = request.files["file"]
    if f.filename.lower().endswith(".php"):
        abort(400)
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in [".exe", ".php"]:
        abort(400)
    name = f.filename.casefold()
    if name.endswith(".sh"):
        abort(400)
    return "ok"
