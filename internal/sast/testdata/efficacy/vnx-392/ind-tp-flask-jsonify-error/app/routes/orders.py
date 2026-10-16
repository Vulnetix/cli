from flask import Blueprint, jsonify, request

from app.models import Order, db

bp = Blueprint("orders", __name__)


@bp.route("/orders", methods=["POST"])
def create_order():
    payload = request.get_json()
    try:
        order = Order(**payload)
        db.session.add(order)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
~>        return jsonify({"error": str(e)})
    return jsonify(order.to_dict()), 201
