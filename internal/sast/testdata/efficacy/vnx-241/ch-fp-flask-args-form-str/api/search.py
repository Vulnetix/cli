from flask import Blueprint, request, jsonify

bp = Blueprint("search", __name__)


@bp.get("/search")
def search():
    q = request.args.get("q", "").lower()
    name = request.form["name"].strip()
    body = request.get_json()
    title = str(body.get("title", ""))
    slug = title.lower()
    raw = body.get("note")
    if not isinstance(raw, str):
        return jsonify(error="note must be a string"), 400
    note = raw.strip()
    return jsonify(q=q, name=name, slug=slug, note=note)
