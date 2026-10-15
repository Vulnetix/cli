from flask import request

from .models import Order, db


def place_order():
    order = Order(user_id=request.json["user_id"])
~>    order.total = float(request.form["total"])
    db.session.add(order)
    db.session.commit()
    return {"id": order.id}
