from flask import Blueprint, request, jsonify

from .db import get_db

bp = Blueprint("orders", __name__)


@bp.route("/orders/<int:order_id>")
def show(order_id):
    db = get_db()
    cur = db.cursor()
~>    cur.execute("SELECT id, total FROM orders WHERE id = %s", (order_id,))
    row = cur.fetchone()
    cur.execute("SELECT * FROM lines WHERE order_id = %s", (order_id,))
    return jsonify(row)
