import logging
import traceback

from flask import Blueprint, jsonify

from .models import Order

bp = Blueprint("orders", __name__)
log = logging.getLogger(__name__)


@bp.route("/orders/<int:order_id>")
def get_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        return jsonify(order.to_dict())
    except Exception:
        log.warning("order lookup failed for %s", order_id)
~>        return jsonify({"error": "lookup failed", "detail": traceback.format_exc()}), 500
