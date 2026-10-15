import os

from flask import Blueprint, request, abort

bp = Blueprint("uploads", __name__)

BLOCKED_EXTENSIONS = {
    ".php",
    ".phtml",
    ".exe",
    ".sh",
}


@bp.post("/upload")
def upload():
    f = request.files["document"]
    ext = os.path.splitext(f.filename)[1]
~>    if ext in BLOCKED_EXTENSIONS:
        abort(400, "file type not allowed")
    f.save(os.path.join("/srv/uploads", f.filename))
    return "", 204
