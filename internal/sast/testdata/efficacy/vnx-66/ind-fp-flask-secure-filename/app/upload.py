import os

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

bp = Blueprint("upload", __name__)


@bp.route("/documents", methods=["POST"])
def upload_document():
    f = request.files["document"]
    name = secure_filename(f.filename)
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], name))
    return jsonify(stored=name), 201
