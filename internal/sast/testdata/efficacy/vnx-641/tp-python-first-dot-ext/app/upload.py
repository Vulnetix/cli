from flask import request

ALLOWED = {"png", "jpg", "gif"}


def upload():
    f = request.files["avatar"]
~>    ext = f.filename.split(".")[1].lower()
    if ext not in ALLOWED:
        return "bad type", 400
~>    if ".png" in f.filename or ".jpg" in f.filename:
        f.save("/srv/uploads/" + secure_name())
    filename = f.filename
~>    stem, _, extension = filename.partition(".")
~>    suffix = filename.split('.', 1)[1]
    return "ok"
