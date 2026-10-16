from flask import Blueprint, jsonify, request

from .rendering import render_page

bp = Blueprint("report", __name__)

MAX_PAGES = 50


@bp.route("/report/preview")
def preview():
    pages = min(int(request.args.get("pages", 1)), MAX_PAGES)
    out = []
    for page in range(pages):
        out.append(render_page(page))
    return jsonify(pages=out)
