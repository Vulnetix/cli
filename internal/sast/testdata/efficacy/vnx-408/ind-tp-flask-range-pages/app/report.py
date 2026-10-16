from flask import Blueprint, jsonify, request

from .rendering import render_page

bp = Blueprint("report", __name__)


@bp.route("/report/preview")
def preview():
    pages = int(request.args.get("pages", 1))
    out = []
~>    for page in range(pages):
        out.append(render_page(page))
    return jsonify(pages=out)
