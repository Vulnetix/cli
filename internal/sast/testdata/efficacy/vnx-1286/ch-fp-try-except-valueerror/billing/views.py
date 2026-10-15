from flask import Blueprint, request, abort, jsonify

bp = Blueprint("billing", __name__)


@bp.route("/invoices", methods=["POST"])
def create_invoice():
    try:
        amount = float(request.form["amount"])
        qty = int(request.form.get("qty", "1"))
    except (KeyError, ValueError):
        abort(400)
    return jsonify(total=amount * qty)


@bp.route("/page")
def page():
    page = request.args.get("page", 1, type=int)
    size = int(PAGE_SIZE)
    return jsonify(page=page, size=size)
