import os
from pathlib import Path

from fastapi import UploadFile
from flask import request

UPLOAD_DIR = "/srv/uploads"


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["document"]
~>    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "ok"


@app.route("/avatar", methods=["POST"])
def avatar():
    pic = request.files.get("avatar")
    name = pic.filename
~>    with open(os.path.join(UPLOAD_DIR, name), "wb") as out:
        out.write(pic.read())
    return "ok"


async def store(file: UploadFile):
~>    target = Path(UPLOAD_DIR) / file.filename
    target.write_bytes(await file.read())
