import os
import re

from flask import abort, request

BLOCKED_EXTENSIONS = {".php", ".phtml", ".jsp", ".exe"}


def upload():
    f = request.files["file"]
    if re.search(r"\.(php|phtml|exe)$", f.filename, re.IGNORECASE):
        abort(400)
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        abort(400)
    f.save(os.path.join("/srv/uploads", f.filename))
