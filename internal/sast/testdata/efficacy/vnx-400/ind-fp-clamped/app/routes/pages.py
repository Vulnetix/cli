from flask import Blueprint, jsonify, request

pages_bp = Blueprint("pages", __name__)
MAX_COUNT = 100


@pages_bp.get("/items")
def items():
    n = min(request.args.get("count", 10, type=int), MAX_COUNT)
    return jsonify([i for i in range(n)])


@pages_bp.get("/fill")
def fill():
    width = request.args.get("width", 10, type=int)
    if width > 80:
        return jsonify(error="too wide"), 400
    return "-" * width
