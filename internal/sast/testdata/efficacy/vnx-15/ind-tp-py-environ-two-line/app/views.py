import os

from flask import Blueprint, jsonify, request

bp = Blueprint("prefs", __name__)


@bp.route("/prefs/locale", methods=["POST"])
def set_locale():
    lang = request.form.get("lang", "en_US.UTF-8")
    current = os.environ.get("LC_ALL")
~>    os.environ["LC_ALL"] = lang
    return jsonify(previous=current, now=lang)
