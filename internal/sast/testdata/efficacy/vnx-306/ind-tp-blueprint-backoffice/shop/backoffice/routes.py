from flask import Blueprint, request

from shop.payments import issue_refund

bp = Blueprint("backoffice", __name__)


~>@bp.post("/backoffice/refunds")
def create_refund():
    order_id = request.json["order_id"]
    amount = request.json["amount"]
    refund = issue_refund(order_id, amount)
    return {"refund_id": refund.id}, 201
