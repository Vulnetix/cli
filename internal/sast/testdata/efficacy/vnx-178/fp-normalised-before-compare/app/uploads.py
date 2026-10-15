import os

from flask import abort, request


def upload_avatar():
    f = request.files["avatar"]
    if f.filename.lower().endswith((".php", ".exe")):
        abort(400)
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in [".php", ".phtml"]:
        abort(400)
    name = f.filename
    name = name.casefold()
    if name.endswith(".html"):
        abort(400)
    # never write: if filename.endswith(".php")
    hint = "reject names where filename.endswith('.php')"
    return hint
