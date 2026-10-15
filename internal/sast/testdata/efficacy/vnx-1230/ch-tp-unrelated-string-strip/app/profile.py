import os

from flask import Blueprint, request, redirect

bp = Blueprint("profile", __name__)
UPLOADS = "/var/www/static/avatars"


@bp.route("/profile", methods=["POST"])
def update_profile():
    display = request.form.get("display_name", "").strip()
    avatar = request.files["avatar"]
    if avatar.filename.lower().endswith((".png", ".jpg")):
~>        avatar.save(os.path.join(UPLOADS, f"{display}.png"))
    return redirect("/profile")
