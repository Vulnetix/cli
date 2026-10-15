import os
from flask import Blueprint, request, redirect
from werkzeug.utils import secure_filename

bp = Blueprint("profile", __name__)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


@bp.route("/avatar", methods=["POST"])
def avatar():
    f = request.files["avatar"]
    name = secure_filename(f.filename)
~>    f.save(os.path.join("static/avatars", name))
    return redirect("/me")


@bp.route("/banner", methods=["POST"])
def banner():
~>    request.files.get("banner").save(
        os.path.join("static/banners", secure_filename(request.files["banner"].filename))
    )
    return redirect("/me")
