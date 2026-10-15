import os

from flask import abort, request


def modules(root):
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)


def upload():
    f = request.files["file"]
    if not f.filename.lower().endswith((".png", ".jpg")):
        abort(400)
    if f.filename.endswith(".png"):
        kind = "image"
    return kind
