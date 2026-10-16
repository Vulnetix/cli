import os

from flask import abort, current_app, request
from werkzeug.utils import secure_filename


@app.route("/attachments", methods=["POST"])
def upload_attachment():
    f = request.files["attachment"]
~>    if f.filename.endswith((".php", ".phtml", ".exe", ".sh")):
        abort(400, "file type not allowed")
    name = secure_filename(f.filename)
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], name))
    return {"stored": name}, 201
