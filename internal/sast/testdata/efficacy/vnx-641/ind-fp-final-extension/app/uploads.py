import os
import uuid

from flask import Flask, abort, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/avatar", methods=["POST"])
def avatar():
    f = request.files["avatar"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in {".png", ".jpg", ".gif"}:
        abort(400)
    base, last = f.filename.rsplit(".", 1)
    tail = f.filename.split(".")[-1]
    if not f.filename.lower().endswith((".png", ".jpg")):
        abort(400)
    f.save(os.path.join(UPLOADS, f"{uuid.uuid4().hex}{ext}"))
    return "", 201
