from datetime import datetime
from flask import Blueprint, request, jsonify

bp = Blueprint("billing", __name__)


@bp.route("/invoices", methods=["POST"])
def create_invoice():
~>    amount = float(request.form["amount"])
~>    due = datetime.strptime(request.form["due"], "%Y-%m-%d")
    return jsonify(amount=amount, due=due.isoformat())


@bp.route("/invoices/import", methods=["POST"])
def import_invoices():
~>    rows = json.loads(request.data)
    return jsonify(count=len(rows))
