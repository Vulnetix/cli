import os
import uuid
import zipfile

from flask import Flask, request, jsonify

app = Flask(__name__)
UPLOAD_DIR = "/srv/imports"


@app.post("/imports")
def import_bundle():
    upload = request.files["bundle"]
    dest = os.path.join(UPLOAD_DIR, uuid.uuid4().hex)
    os.makedirs(dest)
    with zipfile.ZipFile(upload) as zf:
~>        zf.extractall(dest)
    return jsonify(path=dest)
