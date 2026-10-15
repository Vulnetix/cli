import os
import uuid

from flask import request
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/srv/uploads"


def upload():
    f = request.files["document"]
    f.save(os.path.join(UPLOAD_DIR, secure_filename(f.filename)))
    name = secure_filename(f.filename)
    with open(os.path.join(UPLOAD_DIR, name), "wb") as out:
        out.write(f.read())
    ext = os.path.splitext(f.filename)[1]
    f.save(os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}{ext}"))
    app.logger.info("stored %s", f.filename)
    return {"original": f.filename}
