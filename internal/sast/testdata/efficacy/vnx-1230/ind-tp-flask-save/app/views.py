import os
from flask import Blueprint, request, current_app

bp = Blueprint("pics", __name__)
ALLOWED = {".png", ".jpg", ".jpeg"}


@bp.route("/photo", methods=["POST"])
def upload_photo():
    f = request.files["photo"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED:
        return "bad type", 415
~>    f.save(os.path.join(current_app.config["PHOTO_DIR"], "p" + ext))
    return "ok"
