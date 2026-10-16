from flask import request


def upload():
    f = request.files["file"]
~>    ext = f.filename.split(".")[1].lower()
    if ext in {"png", "jpg"}:
        f.save("/srv/up/" + f.filename)
