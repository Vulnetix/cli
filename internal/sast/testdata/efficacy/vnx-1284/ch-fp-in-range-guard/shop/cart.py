from flask import abort, request


def add(cart, product):
    qty = int(request.form["quantity"])
    if qty not in range(1, 100):
        abort(400)
    cart.total += product.price * qty
    return cart
