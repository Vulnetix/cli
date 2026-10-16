import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_ROOT = "/srv/uploads"


@app.post("/upload")
def upload():
    f = request.files["file"]
    upload_dir = os.path.join(UPLOAD_ROOT, request.form["project"])
    os.makedirs(upload_dir, exist_ok=True)
~>    os.chmod(upload_dir, 0o777)
    dest = os.path.join(upload_dir, secure_filename(f.filename))
    f.save(dest)
    return {"saved": dest}
