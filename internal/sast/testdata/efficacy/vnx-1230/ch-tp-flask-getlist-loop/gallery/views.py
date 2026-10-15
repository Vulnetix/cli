import os
import uuid

from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("gallery", __name__)
ALLOWED = {".jpg", ".jpeg", ".png", ".heic"}


@bp.route("/albums/<int:album_id>/photos", methods=["POST"])
def add_photos(album_id):
    saved = []
    for item in request.files.getlist("photos"):
        ext = os.path.splitext(item.filename)[1].lower()
        if ext not in ALLOWED:
            continue
        name = f"{uuid.uuid4().hex}{ext}"
~>        item.save(os.path.join(current_app.config["MEDIA_ROOT"], name))
        saved.append(name)
    return jsonify(saved=saved)
