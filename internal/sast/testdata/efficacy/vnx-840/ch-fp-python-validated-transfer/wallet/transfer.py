from decimal import Decimal

from flask import abort, request

from .models import Account


def transfer():
    src = Account.query.get(request.json["from"])
    dst = Account.query.get(request.json["to"])
    amount = Decimal(request.json["amount"])
    if amount <= 0 or amount > src.balance:
        abort(400)
    src.balance -= amount
    dst.balance += amount
    return {"ok": True}
