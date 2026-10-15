import os

from flask import abort, request

BLOCKED = [".exe", ".sh", ".php"]


def store():
    upload = request.files.get("media")
    ext = os.path.splitext(upload.filename)[1]
~>    if ext in [".exe", ".bat", ".php", ".phtml"]:
        abort(415)
~>    if ext in BLOCKED:
        abort(415)
    upload.save(os.path.join("media", upload.filename))
