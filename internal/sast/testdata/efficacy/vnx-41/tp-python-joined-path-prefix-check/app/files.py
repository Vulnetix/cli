import os
from pathlib import Path

from flask import abort, request, send_file

UPLOAD_DIR = "/srv/uploads"
BASE = Path("/srv/reports")


def download():
    full = os.path.join(UPLOAD_DIR, request.args["name"])
~>    if not full.startswith(UPLOAD_DIR):
        abort(403)
    return send_file(full)


def preview(name):
~>    if os.path.join(UPLOAD_DIR, name).startswith(UPLOAD_DIR):
        return open(os.path.join(UPLOAD_DIR, name)).read()


def report(name):
    target = BASE / name
~>    if not target.is_relative_to(BASE):
        abort(403)
    return target.read_text()
