import pdb

from flask import request


def checkout():
    cart = request.get_json()
~>    pdb.set_trace()
    return {"total": sum(i["price"] for i in cart["items"])}


def refund(order):
~>    import pdb; pdb.set_trace()
    return order.refund()
