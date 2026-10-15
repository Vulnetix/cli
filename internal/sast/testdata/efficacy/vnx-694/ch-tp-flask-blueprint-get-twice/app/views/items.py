from flask import Blueprint, jsonify

bp = Blueprint("items", __name__)


@bp.get("/items")
def list_items():
    return jsonify([])


~>@bp.get("/items")
def list_items_v2():
    return jsonify({"items": []})
