import os

from flask import abort, request


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in [".php", ".phtml", ".exe"]:
        abort(400)
    if f.filename.lower().endswith(".sh"):
        abort(400)
    f.save(os.path.join("/srv/uploads", os.urandom(8).hex() + ext))
    return "", 204
