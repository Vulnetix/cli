from flask import Blueprint, jsonify, request

from .db import get_db

bp = Blueprint("invoices", __name__)


@bp.route("/invoice")
def invoice():
    invoice_id = request.args.get("id")
    cur = get_db().cursor()
~>    cur.execute("SELECT number, total FROM invoices WHERE id = %s", (invoice_id,))
    return jsonify(cur.fetchone())


@bp.route("/invoice/delete", methods=["POST"])
def delete_invoice():
    target = request.form["invoice"]
    db = get_db()
    db.execute(
~>        "DELETE FROM invoices WHERE invoice_id = ?",
        (target,),
    )
    db.commit()
    return "", 204
