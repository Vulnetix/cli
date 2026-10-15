import os
from flask import request, abort

DENY = {".php", ".exe", ".sh"}


def upload():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].casefold()
    if ext in DENY:
        abort(400)
    f.save("/srv/uploads/" + secure_name())
