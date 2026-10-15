from flask import Blueprint, jsonify, request

bp = Blueprint("orders", __name__)


@bp.route("/orders", methods=["POST"])
def create_order():
    try:
        order = Order.from_json(request.get_json())
        order.save()
    except ValueError as e:
~>        return jsonify({"error": str(e)})
    except Exception:
~>        return jsonify(success=False, message="internal error")
    return jsonify(order.to_dict()), 201
