import logging
import traceback
import uuid

from flask import Blueprint, jsonify

bp = Blueprint("orders", __name__)
log = logging.getLogger(__name__)


@bp.route("/orders/<int:order_id>")
def get_order(order_id):
    rid = uuid.uuid4().hex
    try:
        return jsonify(load_order(order_id))
    except Exception:
        log.error("order lookup failed rid=%s\n%s", rid, traceback.format_exc())
        return jsonify({"error": "internal error", "request_id": rid}), 500
