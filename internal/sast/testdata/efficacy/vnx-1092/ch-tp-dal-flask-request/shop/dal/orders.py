~>from flask import jsonify, request

from shop.db import get_db


def list_orders():
~>    status = request.args.get("status", "open")
    db = get_db()
    return db.execute("SELECT * FROM orders WHERE status = ?", (status,)).fetchall()
