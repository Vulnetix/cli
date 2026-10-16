import os

from flask import Blueprint, jsonify, request

BASE = "/srv/app/templates"
bp = Blueprint("templates", __name__)


@bp.route("/template")
def get_template():
    full = os.path.join(BASE, request.args["name"])
    app_version = "1.4"
~>    with open(full) as fh:
        body = fh.read()
    return jsonify(version=app_version, body=body)
