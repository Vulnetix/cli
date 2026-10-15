import os

from flask import request, redirect
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"png", "jpg", "pdf"}


def allowed_file(filename):
~>    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def upload():
    f = request.files["file"]
~>    if f.filename.endswith((".png", ".jpg")):
        f.save(os.path.join("uploads", secure_filename(f.filename)))
    return redirect("/")
