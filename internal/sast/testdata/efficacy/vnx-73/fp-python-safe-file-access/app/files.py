import os

from flask import abort, request, send_from_directory
from werkzeug.utils import secure_filename

UPLOADS = "/srv/uploads"
ALLOWED = {"terms.txt", "privacy.txt"}


def download():
    return send_from_directory(UPLOADS, request.args["f"])


def view():
    name = secure_filename(request.args["name"])
    with open(os.path.join(UPLOADS, name)) as fh:
        return fh.read()


def log():
    with open("/var/log/app.log", "a") as fh:
        fh.write(request.args["msg"])


def doc():
    doc = request.args.get("doc")
    if doc not in ALLOWED:
        abort(404)
    return open(os.path.join(UPLOADS, doc)).read()
