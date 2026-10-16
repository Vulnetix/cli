import pdb

from flask import jsonify, request


def checkout():
    cart = request.get_json()
~>    pdb.set_trace()
    total = sum(i["price"] for i in cart["items"])
    return jsonify(total=total)


def refund(order):
~>    breakpoint()
    return order
