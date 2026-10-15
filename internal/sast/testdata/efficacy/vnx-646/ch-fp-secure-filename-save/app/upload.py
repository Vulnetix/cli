import os
from flask import request
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/srv/uploads"


def save_upload():
    f = request.files["file"]
    filename = secure_filename(f.filename)
    if filename == "":
        return "no file", 400
    f.save(os.path.join(UPLOAD_DIR, filename))
    return "ok"
