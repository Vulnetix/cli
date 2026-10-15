import os

from flask import abort, request

UPLOAD_DIR = "/srv/uploads"


def upload_avatar():
    f = request.files["avatar"]
    filename = f.filename
~>    if filename.endswith((".php", ".exe", ".sh")):
        abort(400)
    f.save(os.path.join(UPLOAD_DIR, filename))


def upload_doc():
    f = request.files["doc"]
    ext = os.path.splitext(f.filename)[1]
~>    if ext in [".php", ".phtml", ".py"]:
        abort(400)
~>    if ext == '.html':
        abort(400)
    f.save(os.path.join(UPLOAD_DIR, f.filename))
