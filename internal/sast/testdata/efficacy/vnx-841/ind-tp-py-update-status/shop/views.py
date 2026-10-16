from flask import request

def set_state(order_id):
    new_state = request.form["status"]
~>    Order.objects.filter(id=order_id).update(status=request.form["status"])
    return "ok"
