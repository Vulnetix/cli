import os

from flask import abort, request

BLOCKED_EXTENSIONS = {".php", ".phtml", ".jsp", ".exe"}


def upload():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1]
~>    if ext in BLOCKED_EXTENSIONS:
        abort(400)
    f.save(os.path.join("/srv/uploads", f.filename))
