import os

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("upload", __name__)


@bp.route("/documents", methods=["POST"])
def upload_document():
    f = request.files["document"]
    upload_dir = current_app.config["UPLOAD_DIR"]
~>    f.save(os.path.join(upload_dir, f.filename))
    return jsonify(stored=f.filename), 201
