import json
import os

from flask import Blueprint, abort, jsonify, request

bp = Blueprint("search", __name__)

WORKERS = int(os.environ.get("SEARCH_WORKERS", "4"))


@bp.route("/search")
def search():
    page = request.args.get("page", 1, type=int)
    try:
        size = int(request.args["size"])
    except (KeyError, ValueError):
        size = 25
    raw_year = request.args.get("year", "")
    if not raw_year.isdigit():
        abort(400)
    year = int(raw_year)
    try:
        filters = json.loads(request.form.get("filters", "{}"))
    except json.JSONDecodeError:
        abort(400)
    return jsonify(run_search(page, size, year, filters, WORKERS))
