import magic
from flask import request


def upload():
    f = request.files["file"]
    head = f.stream.read(2048)
    f.stream.seek(0)
    if magic.from_buffer(head, mime=True) not in {"image/png", "image/jpeg"}:
        return "bad", 415
    if not f.filename.lower().endswith((".png", ".jpg")):
        return "bad", 415
    f.save("/srv/uploads/x")
