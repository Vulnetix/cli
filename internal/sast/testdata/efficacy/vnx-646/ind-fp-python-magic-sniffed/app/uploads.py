import magic
from flask import request, abort

ALLOWED_EXTENSIONS = {"pdf"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def receive():
    f = request.files["doc"]
    head = f.stream.read(2048)
    f.stream.seek(0)
    if magic.from_buffer(head, mime=True) != "application/pdf":
        abort(415)
    if not allowed_file(f.filename):
        abort(415)
    store(f)
