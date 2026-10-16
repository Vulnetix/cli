import json

from flask import Blueprint, jsonify, request

from app.models import Product

bp = Blueprint("catalog", __name__)


@bp.route("/products")
def list_products():
~>    page = int(request.args.get("page"))
    per_page = request.args.get("per_page", "20")
~>    limit = int(per_page)
    items = Product.query.offset(page * limit).limit(limit).all()
    return jsonify([p.to_dict() for p in items])


@bp.route("/products/bulk", methods=["POST"])
def bulk_update():
~>    payload = json.loads(request.data)
    for row in payload["items"]:
        Product.update_price(row["sku"], row["price"])
    return jsonify(ok=True)
