from flask import Blueprint, jsonify

bp = Blueprint("orders", __name__)


@bp.post("/orders")
def create_order():
    try:
        order = service.create()
    except DatabaseError:
~>        return jsonify({"success": False, "message": "Could not save the order"})
    return jsonify(order.to_dict()), 201


@bp.delete("/orders/<oid>")
def delete_order(oid):
    try:
        service.delete(oid)
    except Exception:
~>        return jsonify(message="Something went wrong, unable to delete")
    return "", 204
