import filetype
from flask import request

ALLOWED = {"png", "jpg"}


def upload():
    f = request.files["image"]
    head = f.stream.read(261)
    kind = filetype.guess(head)
    if kind is None or kind.extension not in ALLOWED:
        return "bad image", 400
    if not f.filename.lower().endswith((".png", ".jpg")):
        return "rename the file", 400
    return "ok"
