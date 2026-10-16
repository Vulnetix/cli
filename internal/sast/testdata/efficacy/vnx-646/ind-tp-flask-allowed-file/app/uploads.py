import os

from flask import Flask, request, redirect
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "/srv/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
~>    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["photo"]
    if file and allowed_file(file.filename):
        name = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], name))
        return redirect("/gallery")
    return "bad file", 400
