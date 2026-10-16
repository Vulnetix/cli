import os

from flask import abort, request, send_file

UPLOAD_DIR = "/srv/uploads"


def download():
    full = os.path.join(UPLOAD_DIR, request.args["name"])
~>    if not full.startswith(UPLOAD_DIR):
        abort(403)
    return send_file(full)
