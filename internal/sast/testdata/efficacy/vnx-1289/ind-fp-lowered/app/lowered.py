import os
from flask import request, abort


def upload():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in [".exe", ".php"]:
        abort(400)
    if f.filename.lower().endswith(".jsp"):
        abort(400)
    if f.filename.casefold().endswith((".html", ".htm")):
        abort(400)
