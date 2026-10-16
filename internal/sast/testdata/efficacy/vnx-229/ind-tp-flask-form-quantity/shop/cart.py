from flask import Blueprint, request, jsonify

bp = Blueprint("cart", __name__)


@bp.route("/cart/items", methods=["POST"])
def add_item():
    sku = request.form["sku"]
~>    qty = int(request.form["quantity"])
    cart = get_cart()
    cart.add(sku, qty)
    return jsonify(cart.to_dict())
