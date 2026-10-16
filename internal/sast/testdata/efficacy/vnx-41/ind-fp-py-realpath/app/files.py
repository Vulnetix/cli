import os
from pathlib import Path

from flask import abort, request, send_file

UPLOAD_DIR = os.path.realpath("/srv/uploads")
BASE = Path("/srv/reports").resolve()


def download():
    full = os.path.join(UPLOAD_DIR, request.args["name"])
    full = os.path.realpath(full)
    if not full.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    return send_file(full)


def report(name):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        abort(404)
    return send_file(target)
