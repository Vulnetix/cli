from flask import Blueprint, jsonify
from .models import db, Order

bp = Blueprint("ops", __name__)


~>@bp.route("/admin/orders/purge", methods=["POST"])
def purge_orders():
    Order.query.delete()
    db.session.commit()
    return jsonify(ok=True)
