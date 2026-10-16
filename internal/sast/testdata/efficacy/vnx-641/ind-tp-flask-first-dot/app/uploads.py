import os
import uuid

from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED = {".png", ".jpg", ".gif"}
UPLOADS = "/srv/uploads"


@app.route("/avatar", methods=["POST"])
def avatar():
    f = request.files["avatar"]
~>    ext = f.filename.split(".")[1].lower()
    if ext not in {"png", "jpg", "gif"}:
        abort(400)
    f.save(os.path.join(UPLOADS, f"{uuid.uuid4().hex}.{ext}"))
    return "", 201


@app.route("/attachment", methods=["POST"])
def attachment():
    upload = request.files["file"]
    filename = upload.filename
~>    if not any(ext in filename for ext in ALLOWED):
        abort(400)
~>    if ".png" in upload.filename:
        kind = "image"
    upload.save(os.path.join(UPLOADS, uuid.uuid4().hex))
    return "", 201
