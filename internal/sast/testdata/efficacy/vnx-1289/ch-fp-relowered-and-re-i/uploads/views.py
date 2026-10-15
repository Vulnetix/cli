import os
import re

from flask import request, abort

DENY = (".php", ".exe", ".sh")


def upload():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1]
    ext = ext.lower()
    if ext in DENY:
        abort(400)
    if re.search(r"\.(php|exe)$", f.filename, re.IGNORECASE):
        abort(400)
    if re.search(r"(?i)\.(cgi|pl)$", f.filename):
        abort(400)
    f.save("/srv/" + f.filename)
