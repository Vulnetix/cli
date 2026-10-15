from flask import Blueprint, jsonify

from shop.db import get_db

bp = Blueprint("orders", __name__)


@bp.route("/orders/<int:oid>")
def order(oid):
    db = get_db()
    sql = "SELECT id, total FROM orders WHERE id = ?"
~>    row = db.execute(sql, (oid,)).fetchone()
    return jsonify(dict(row))
